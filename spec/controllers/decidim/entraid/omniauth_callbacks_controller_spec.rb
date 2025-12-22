# frozen_string_literal: true

require "spec_helper"

module Decidim
  module EntraID
    # Tests the controller as well as the underlying OAuth integration in order
    # to ensure that the OmniAuth strategy is correctly loading the attribute
    # values from the Microsoft Graph response. Note that this is why we are
    # using the `:request` type instead of `:controller`, so that we get the
    # OmniAuth middleware applied to the requests and the EntraID OmniAuth
    # strategy to handle the OAuth + Microsoft Graph interaction with the Entra
    # ID endpoints.
    describe OmniauthCallbacksController, type: :request do
      let(:organization) { create(:organization) }
      let(:current_user) do
        warden = request.env["warden"]
        warden.authenticate(scope: :user)
      end

      include_context "with EntraID authentication flow"

      before do
        host! organization.host
      end

      describe "GET entraid" do
        it "creates a new user record with correct information" do
          expect { omniauth_callback }.to change(User, :count).by(1)
          expect(response).to redirect_to("/")

          user = User.order(:id).last
          expect(user).not_to be_nil

          expect(user.email).to eq(entra_identity.email)
          expect(user.name).to eq(entra_identity.name)

          expected_nick = entra_identity.name.parameterize(separator: "_")[0..20]
          expect(user.nickname).to eq(expected_nick)
        end

        it "signs in the user" do
          omniauth_callback

          expect(current_user.email).to eq(entra_identity.email)
          expect(current_user.sign_in_count).to eq(1)
        end

        it "creates an identity for the user" do
          expect { omniauth_callback }.to change(Identity, :count).by(1)

          expect(current_user.identities.count).to eq(1)

          identity = current_user.identities.first
          expect(identity.provider).to eq(entra_tenant.name)
          expect(identity.uid).to eq("#{entra_tenant.tenant_id}.#{entra_identity.oid}")
        end

        it "authorizes the user with the collected metadata" do
          expect { omniauth_callback }.to change(Authorization, :count).by(1)

          authorization = Authorization.find_by(
            user: current_user,
            name: "entraid_identity"
          )
          expect(authorization).not_to be_nil
          expect(authorization.metadata).to match(
            "surname" => entra_identity.family_name,
            "given_name" => entra_identity.given_name,
            "display_name" => entra_identity.display_name,
            "principal_name" => entra_identity.principal_name
          )
        end

        context "when the session has a pending redirect" do
          let(:after_sign_in_path) { "/processes" }

          before do
            # Do a mock request in order to create a session
            get "/"
            # session["user_return_to"] = after_sign_in_path
            request.session["user_return_to"] = after_sign_in_path
          end

          it "redirects to the stored location by default after a successful registration and first sign in" do
            omniauth_callback(
              env: {
                "rack.session" => request.session,
                "rack.session.options" => request.session.options
              }
            )

            expect(current_user).not_to be_nil
            expect(current_user.sign_in_count).to eq(1)
            expect(response).to redirect_to("/processes")
          end
        end

        context "when a user already exists with a matching identity" do
          let!(:existing_user) { create(:user, :confirmed, organization:) }
          let!(:existing_identity) do
            create(
              :identity,
              provider: "entraid",
              uid: "#{entra_tenant.tenant_id}.#{entra_identity.oid}",
              user: existing_user
            )
          end

          it "signs in the existing user" do
            expect { omniauth_callback }.not_to change(User, :count)

            expect(current_user.id).to eq(existing_user.id)
          end

          it "does not update the existing user details" do
            omniauth_callback

            expect(current_user.name).not_to eq(entra_identity.name)
          end

          it "authorizes the existing user" do
            expect { omniauth_callback }.to change(Authorization, :count).by(1)

            authorization = Authorization.find_by(
              user: current_user,
              name: "entraid_identity"
            )
            expect(authorization).not_to be_nil
          end
        end

        context "when the user is already signed in" do
          let!(:existing_user) { create(:user, :confirmed, organization:) }

          before do
            sign_in existing_user
          end

          it "adds an identity for the signed in user" do
            expect(existing_user.identities.count).to eq(0)
            expect { omniauth_callback }.to change(Identity, :count).by(1)
            expect(existing_user.identities.count).to eq(1)

            identity = existing_user.identities.first
            expect(identity.provider).to eq("entraid")
            expect(identity.uid).to eq("#{entra_tenant.tenant_id}.#{entra_identity.oid}")
          end

          it "authorizes the user" do
            expect(Decidim::Authorization.where(user: existing_user).count).to eq(0)
            expect { omniauth_callback }.to change(Authorization, :count).by(1)
            expect(Decidim::Authorization.where(user: existing_user).count).to eq(1)

            authorization = Authorization.find_by(
              user: current_user,
              name: "entraid_identity"
            )
            expect(authorization).not_to be_nil
          end

          context "and another user is already identified with the same identity" do
            let!(:another_user) { create(:user, :confirmed, organization:) }
            let!(:another_user_identity) do
              create(
                :identity,
                provider: "entraid",
                uid: "#{entra_tenant.tenant_id}.#{entra_identity.oid}",
                user: another_user
              )
            end

            it "prevents the authorization with correct error message" do
              expect { omniauth_callback }.not_to change(Authorization, :count)

              authorization = Authorization.find_by(
                user: existing_user,
                name: "entraid_identity"
              )
              expect(authorization).to be_nil
              expect(response).to redirect_to("/users/auth/entraid/logout")
              expect(flash[:alert]).to eq(
                "Another user has already been identified using this identity. Please sign out and sign in again directly using Entra ID."
              )
            end
          end

          context "and another user is already authorized with the same identity" do
            let!(:another_user) { create(:user, :confirmed, organization:) }
            let(:uid) { "#{entra_tenant.tenant_id}.#{entra_identity.oid}" }
            let!(:another_user_authorization) do
              signature = OmniauthRegistrationForm.create_signature(:entraid, uid)
              authorization = Decidim::Authorization.create!(
                user: another_user,
                name: "entraid_identity",
                attributes: {
                  unique_id: signature,
                  metadata: {}
                }
              )
              authorization.save!
              authorization.grant!
              authorization
            end

            it "prevents the authorization with correct error message" do
              expect { omniauth_callback }.not_to change(Authorization, :count)

              authorization = Authorization.find_by(
                user: existing_user,
                name: "entraid_identity"
              )
              expect(authorization).to be_nil
              expect(response).to redirect_to("/users/auth/entraid/logout")
              expect(flash[:alert]).to eq(
                "Another user has already authorized themselves with the same identity."
              )
            end
          end
        end

        context "when the user is already signed in and authorized" do
          let!(:existing_user) { create(:user, :confirmed, organization:) }
          let(:uid) { "#{entra_tenant.tenant_id}.#{entra_identity.oid}" }
          let!(:authorization) do
            signature = OmniauthRegistrationForm.create_signature(:entraid, uid)
            authorization = Decidim::Authorization.create!(
              user: existing_user,
              name: "entraid_identity",
              attributes: {
                unique_id: signature,
                metadata: {}
              }
            )
            authorization.save!
            authorization.grant!
            authorization
          end

          before do
            sign_in existing_user
          end

          it "updates the existing authorization" do
            expect { omniauth_callback }.not_to change(Authorization, :count)
            expect(Decidim::Authorization.where(user: existing_user).count).to eq(1)

            # Check that the authorization is the same one
            auth = Authorization.find_by(
              user: existing_user,
              name: "entraid_identity"
            )
            expect(auth).to eq(authorization)

            # Check that the metadata was updated
            expect(auth.metadata).to match(
              "surname" => entra_identity.family_name,
              "given_name" => entra_identity.given_name,
              "display_name" => entra_identity.display_name,
              "principal_name" => entra_identity.principal_name
            )
          end
        end

        context "when the authentication flow fails" do
          context "with invalid_credentials" do
            let(:entra_token_endpoint_stub) do
              stub_request(
                :post,
                "https://login.microsoftonline.com/#{entra_tenant.tenant_id}/oauth2/v2.0/token"
              ).to_return(
                status: 400,
                body: { error: "invalid_grant" }.to_json,
                headers: { "Content-Type" => "application/json" }
              )
            end

            it "redirects to the sign in path with the correct error message" do
              expect { omniauth_callback }.not_to change(Identity, :count)
              expect(current_user).to be_nil

              expect(response).to redirect_to("/users/sign_in")
              expect(flash[:alert]).to eq("Invalid authentication credentials provided. Please contact the system maintainer.")
            end
          end

          # When the state parameter is incorrect
          context "with csrf_detected" do
            it "redirects to the sign in path with the correct error message" do
              expect do
                post "/users/auth/entraid"

                entra_token_endpoint_stub

                callback_params = {
                  code: entra_oidc.generate_authorization_code,
                  state: "foobar",
                  session_state: SecureRandom.uuid
                }
                get "/users/auth/entraid/callback?#{callback_params.to_query}"
              end.not_to change(Identity, :count)
              expect(current_user).to be_nil

              expect(response).to redirect_to("/users/sign_in")
              expect(flash[:alert]).to eq("Invalid authentication state, CSRF detected.")
            end
          end

          context "with failed_to_connect" do
            let(:entra_token_endpoint_stub) do
              stub_request(
                :post,
                "https://login.microsoftonline.com/#{entra_tenant.tenant_id}/oauth2/v2.0/token"
              ).to_raise(::SocketError)
            end

            it "redirects to the sign in path with the correct error message" do
              expect { omniauth_callback }.not_to change(Identity, :count)
              expect(current_user).to be_nil

              expect(response).to redirect_to("/users/sign_in")
              expect(flash[:alert]).to eq("Could not connect to the authentication server.")
            end
          end

          context "with timeout" do
            let(:entra_token_endpoint_stub) do
              stub_request(
                :post,
                "https://login.microsoftonline.com/#{entra_tenant.tenant_id}/oauth2/v2.0/token"
              ).to_raise(::Timeout::Error)
            end

            it "redirects to the sign in path with the correct error message" do
              expect { omniauth_callback }.not_to change(Identity, :count)
              expect(current_user).to be_nil

              expect(response).to redirect_to("/users/sign_in")
              expect(flash[:alert]).to eq("Authentication request timed out.")
            end
          end

          context "with invalid_api_token" do
            let(:entra_graphapi_endpoint_stub) do
              stub_request(
                :get,
                "https://graph.microsoft.com/v1.0/me?$select=displayName,givenName,surname,mail,userPrincipalName"
              ).to_return(
                status: 401,
                body: { error: { code: "InvalidAuthenticationToken" } }.to_json,
                headers: { "Content-Type" => "application/json" }
              )
            end

            it "redirects to the sign in path with the correct error message" do
              expect { omniauth_callback }.not_to change(Identity, :count)
              expect(current_user).to be_nil

              expect(response).to redirect_to("/users/sign_in")
              expect(flash[:alert]).to eq("Invalid token provided for the identity data.")
            end
          end
        end
      end
    end
  end
end
