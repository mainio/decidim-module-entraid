# frozen_string_literal: true

require "spec_helper"

module Decidim
  module EntraID
    module Authentication
      describe Authenticator do
        subject { described_class.new(tenant, organization, oauth_hash, strategy) }

        let(:tenant) { Decidim::EntraID.tenants.first }
        let(:organization) { create(:organization) }
        let(:strategy) { double }
        let(:oauth_hash) do
          {
            provider: oauth_provider,
            uid: oauth_uid,
            info: {
              email: oauth_email,
              name: oauth_name,
              first_name: oauth_first_name,
              last_name: oauth_last_name,
              nickname: oauth_nickname,
              image: oauth_image
            },
            extra: {
              raw_info: oauth_raw_info
            }
          }
        end
        let(:oauth_provider) { "provider" }
        let(:oauth_uid) { "uid" }
        let(:oauth_email) { nil }
        let(:oauth_first_name) { "Marja" }
        let(:oauth_last_name) { "Mainio" }
        let(:oauth_name) { "Marja Mainio" }
        let(:oauth_nickname) { "mmainio" }
        let(:oauth_image) { nil }
        let(:oauth_raw_info) do
          {
            "display_name" => "Marja Mainio",
            "given_name" => "Marja",
            "surname" => "Mainio",
            "mail" => "marja.mainio@example.onmicrosoft.com",
            "user_principal_name" => "marja.mainio@example.onmicrosoft.com"
          }
        end
        let(:configured_metadata_attributes) { nil }

        around do |example|
          orig_attributes = tenant.metadata_attributes
          tenant.metadata_attributes = configured_metadata_attributes

          example.run

          tenant.metadata_attributes = orig_attributes
        end

        describe "#verified_email" do
          context "when email is available in the OAuth info" do
            let(:oauth_email) { "user@example.org" }

            it "returns the email from user attributes" do
              expect(subject.verified_email).to eq("user@example.org")
            end
          end

          context "when email is not available in the user attributes" do
            let(:configured_auto_email_domain) { "1.lvh.me" }

            before do
              allow(tenant).to receive(:auto_email_domain).and_return(configured_auto_email_domain)
            end

            it "auto-creates the email using the known pattern" do
              expect(subject.verified_email).to match(/entraid-[a-z0-9]{32}@1.lvh.me/)
            end

            context "and auto_email_domain is not defined" do
              let(:configured_auto_email_domain) { nil }

              it "auto-creates the email using the known pattern" do
                expect(subject.verified_email).to match(/entraid-[a-z0-9]{32}@#{organization.host}/)
              end
            end
          end
        end

        describe "#user_params_from_oauth_hash" do
          it "returns the expected hash" do
            signature = ::Decidim::OmniauthRegistrationForm.create_signature(
              oauth_provider,
              oauth_uid
            )

            expect(subject.user_params_from_oauth_hash).to include(
              provider: oauth_provider,
              uid: oauth_uid,
              name: oauth_name,
              nickname: oauth_nickname,
              oauth_signature: signature,
              avatar_url: nil,
              raw_data: oauth_hash
            )
          end

          context "when oauth data is empty" do
            let(:oauth_hash) { {} }

            it "returns nil" do
              expect(subject.user_params_from_oauth_hash).to be_nil
            end
          end

          context "when user identifier is blank" do
            let(:oauth_uid) { nil }

            it "returns nil" do
              expect(subject.user_params_from_oauth_hash).to be_nil
            end
          end

          context "when nickname does not exist" do
            let(:oauth_nickname) { nil }

            it "uses name as the nickname" do
              expect(subject.user_params_from_oauth_hash).to include(
                name: oauth_name,
                nickname: oauth_name
              )
            end
          end
        end

        describe "#validate!" do
          it "returns true for valid authentication data" do
            expect(subject.validate!).to be(true)
          end

          context "when an identity already exists" do
            let(:user) { create(:user, :confirmed, organization:) }
            let!(:identity) do
              user.identities.create!(
                organization:,
                provider: oauth_provider,
                uid: oauth_uid
              )
            end

            it "returns true for valid authentication data" do
              expect(subject.validate!).to be(true)
            end
          end

          context "when no user attributes are available" do
            let(:oauth_raw_info) { {} }

            it "raises a ValidationError" do
              expect do
                subject.validate!
              end.to raise_error(
                Decidim::EntraID::Authentication::ValidationError,
                "No data provided"
              )
            end
          end

          context "when all user attributes values are blank" do
            let(:oauth_raw_info) do
              {
                "display_name" => nil,
                "given_name" => nil,
                "surname" => nil,
                "mail" => nil,
                "user_principal_name" => nil
              }
            end

            it "raises a ValidationError" do
              expect do
                subject.validate!
              end.to raise_error(
                Decidim::EntraID::Authentication::ValidationError,
                "Invalid data"
              )
            end
          end

          context "when there is no person identifier" do
            let(:oauth_uid) { nil }

            it "raises a ValidationError" do
              expect do
                subject.validate!
              end.to raise_error(
                Decidim::EntraID::Authentication::ValidationError,
                "Invalid person dentifier"
              )
            end
          end
        end

        describe "#identify_user!" do
          let(:user) { create(:user, :confirmed, organization:) }

          it "creates a new identity for the user" do
            id = subject.identify_user!(user)

            expect(Decidim::Identity.count).to eq(1)
            expect(Decidim::Identity.last.id).to eq(id.id)
            expect(id.organization.id).to eq(organization.id)
            expect(id.user.id).to eq(user.id)
            expect(id.provider).to eq(oauth_provider)
            expect(id.uid).to eq(oauth_uid)
          end

          context "when an identity already exists" do
            let!(:identity) do
              user.identities.create!(
                organization:,
                provider: oauth_provider,
                uid: oauth_uid
              )
            end

            it "returns the same identity" do
              expect(subject.identify_user!(user).id).to eq(identity.id)
            end
          end

          context "when a matching identity already exists for another user" do
            let(:another_user) { create(:user, :confirmed, organization:) }

            before do
              another_user.identities.create!(
                organization:,
                provider: oauth_provider,
                uid: oauth_uid
              )
            end

            it "raises an IdentityBoundToOtherUserError" do
              expect do
                subject.identify_user!(user)
              end.to raise_error(
                Decidim::EntraID::Authentication::IdentityBoundToOtherUserError
              )
            end
          end
        end

        describe "#authorize_user!" do
          let(:user) { create(:user, :confirmed, organization:) }
          let(:signature) do
            ::Decidim::OmniauthRegistrationForm.create_signature(
              oauth_provider,
              oauth_uid
            )
          end

          it "creates a new authorization for the user" do
            auth = subject.authorize_user!(user)

            expect(Decidim::Authorization.count).to eq(1)
            expect(Decidim::Authorization.last.id).to eq(auth.id)
            expect(auth.user.id).to eq(user.id)
            expect(auth.unique_id).to eq(signature)
            expect(auth.metadata).to be_nil
          end

          context "when the metadata collector has been configured to collect attributes" do
            let(:configured_metadata_attributes) do
              {
                display_name: "display_name",
                given_name: "given_name",
                surname: "surname",
                mail: "mail",
                principal_name: "user_principal_name"
              }
            end
            let(:user_attributes) do
              {
                "display_name" => "Marja Mainio",
                "given_name" => "Marja",
                "surname" => "Mainio",
                "mail" => "marja.mainio@example.onmicrosoft.com",
                "user_principal_name" => "marja.mainio@example.onmicrosoft.com"
              }
            end

            it "creates a new authorization for the user with the correct metadata" do
              auth = subject.authorize_user!(user)

              expect(Decidim::Authorization.count).to eq(1)
              expect(Decidim::Authorization.last.id).to eq(auth.id)
              expect(auth.user.id).to eq(user.id)
              expect(auth.unique_id).to eq(signature)
              expect(auth.metadata).to match(
                "display_name" => "Marja Mainio",
                "given_name" => "Marja",
                "surname" => "Mainio",
                "mail" => "marja.mainio@example.onmicrosoft.com",
                "principal_name" => "marja.mainio@example.onmicrosoft.com"
              )
            end
          end

          context "when an authorization already exists" do
            let!(:authorization) do
              Decidim::Authorization.create!(
                name: "entraid_identity",
                user:,
                unique_id: signature
              )
            end

            it "returns the existing authorization and updates it" do
              auth = subject.authorize_user!(user)

              expect(auth.id).to eq(authorization.id)
              expect(auth.metadata).to be_nil
            end
          end

          context "when a matching authorization already exists for another user" do
            let(:another_user) { create(:user, :confirmed, organization:) }

            before do
              Decidim::Authorization.create!(
                name: "entraid_identity",
                user: another_user,
                unique_id: signature
              )
            end

            it "raises an IdentityBoundToOtherUserError" do
              expect do
                subject.authorize_user!(user)
              end.to raise_error(
                Decidim::EntraID::Authentication::AuthorizationBoundToOtherUserError
              )
            end
          end
        end

        describe "#update_user!" do
          let(:oauth_email) { "omniauth@example.org" }

          let(:user) { create(:user, :confirmed, organization:) }
          let(:signature) do
            ::Decidim::OmniauthRegistrationForm.create_signature(
              oauth_provider,
              oauth_uid
            )
          end

          it "updates the user's email address in case it has changed" do
            subject.update_user!(user)

            expect(user.email).to eq(oauth_email)
          end

          it "does not sign the user up to the newsletters" do
            subject.update_user!(user)

            expect(user.newsletter_notifications_at).to be_nil
          end

          context "when signing up new users to newsletters is enabled" do
            before do
              allow(tenant).to receive(:registration_newsletter_subscriptions).and_return(true)
            end

            it "signs up a new user to the newsletters" do
              # Calling validate! sets the @new_user instance variable to true
              # when the identity does not yet exist.
              subject.validate!
              subject.update_user!(user)

              expect(user.newsletter_notifications_at).to be_a(::Time)
            end

            it "does not sign up existing users to the newsletters" do
              subject.update_user!(user)

              expect(user.newsletter_notifications_at).to be_nil
            end
          end
        end
      end
    end
  end
end
