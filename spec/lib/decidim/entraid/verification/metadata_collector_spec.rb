# frozen_string_literal: true

require "spec_helper"

module Decidim
  module EntraID
    module Verification
      describe MetadataCollector do
        subject { described_class.new(tenant, user_attributes, oauth_strategy) }

        let(:tenant) { Decidim::EntraID.tenants.first }
        let(:user_attributes) do
          {
            given_name: "Marja",
            display_name: "Marja Mainio",
            surname: "Mainio",
            user_principal_name: "mmainio@example.onmicrosoft.com"
          }.transform_keys(&:to_s)
        end
        let(:oauth_strategy) { double }

        around do |example|
          orig_attributes = tenant.metadata_attributes
          tenant.metadata_attributes = configured_attributes

          example.run

          tenant.metadata_attributes = orig_attributes
        end

        context "when the module has not been configured to collect the metadata" do
          let(:configured_attributes) { {} }

          it "does not collect any metadata" do
            expect(subject.metadata).to be_nil
          end
        end

        context "when the module has been cofigured to collect the metadata" do
          let(:configured_attributes) do
            {
              display_name: "display_name",
              given_name: "given_name",
              surname: "surname",
              principal_name: "user_principal_name"
            }
          end

          it "collects the correct metadata" do
            expect(subject.metadata).to match(
              display_name: "Marja Mainio",
              given_name: "Marja",
              surname: "Mainio",
              principal_name: "mmainio@example.onmicrosoft.com"
            )
          end
        end
      end
    end
  end
end
