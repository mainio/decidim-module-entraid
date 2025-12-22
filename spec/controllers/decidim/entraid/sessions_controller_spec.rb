# frozen_string_literal: true

require "spec_helper"

module Decidim
  module EntraID
    # Tests the session destroying functionality with the EntraID module.
    # Note that this is why we are using the `:request` type instead
    # of `:controller`, so that we get the OmniAuth middleware applied to the
    # requests and the OmniAuth strategy handles the endpoints. Another reason
    # is to test the sign out path override.
    describe SessionsController, type: :request do
      let(:organization) { create(:organization) }

      # For testing with signed in user
      let(:existing_user) { create(:user, :confirmed, organization:) }

      before do
        # Set the correct host
        host! organization.host
      end

      describe "POST destroy" do
        before do
          sign_in existing_user
        end

        context "when there is no active Entra ID sign in" do
          it "signs out the user normally" do
            post "/users/sign_out"

            expect(response).to redirect_to("/")
            expect(controller.current_user).to be_nil
          end
        end

        context "when there is an active Entra ID sign in" do
          before do
            # Generate a dummy session by requesting the home page.
            get "/"
            request.session["decidim-entraid.signed_in"] = true
            request.session["decidim-entraid.tenant"] = "entraid"
          end

          it "signs out the user through the Entra ID" do
            post "/users/sign_out", env: {
              "rack.session" => request.session,
              "rack.session.options" => request.session.options
            }

            expect(response).to redirect_to("/users/auth/entraid/logout?success=1")
            expect(controller.current_user).to be_nil
          end

          context "with the translation suffix provided as a parameter" do
            it "signs out the user with correct flash message" do
              post "/users/sign_out?translation_suffix=timed_out", env: {
                "rack.session" => request.session,
                "rack.session.options" => request.session.options
              }

              expect(response).to redirect_to("/users/auth/entraid/logout?success=1")
              expect(session.dig("flash", "flashes", "notice")).to eq(
                <<~MSG.gsub("\n", " ").strip
                  You were inactive for too long and you have been automatically
                  logged out from the service. If you would like to continue
                  using the service, please log in again.
                MSG
              )
            end
          end

          context "with an unknown tenant" do
            before do
              request.session["decidim-entraid.tenant"] = "foo"
            end

            it "raises a StandardError" do
              expect do
                post "/users/sign_out", env: {
                  "rack.session" => request.session,
                  "rack.session.options" => request.session.options
                }
              end.to raise_error(
                StandardError,
                "Unkown Entra ID tenant: foo"
              )
            end
          end
        end
      end

      # According to the documentation, the identity platform sends a GET
      # request to this endpoint on all connected services.
      describe "GET front_channel_logout" do
        context "with existing user session" do
          before do
            sign_in existing_user

            # Initiate session
            get "/"
          end

          it "responds with successful payload" do
            get "/users/auth/entraid/fclogout", env: {
              "rack.session" => request.session,
              "rack.session.options" => request.session.options
            }

            expect(response).to have_http_status(:success)
            expect(response.headers["Content-Type"]).to eq("text/plain; charset=utf-8")
            expect(response.body).to eq("Signed out.")
          end
        end

        context "without a user session" do
          it "responds with expected payload" do
            get "/users/auth/entraid/fclogout"

            expect(response).to have_http_status(:success)
            expect(response.headers["Content-Type"]).to eq("text/plain; charset=utf-8")
            expect(response.body).to eq("")
          end
        end
      end
    end
  end
end
