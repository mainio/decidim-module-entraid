# frozen_string_literal: true

require "spec_helper"

module Decidim::EntraID
  describe Tenant do
    it_behaves_like "an EntraID tenant", "entraid"
    it_behaves_like "an EntraID tenant", "other"

    context "with default configuration" do
      subject do
        described_class.new do
          # Add some text to avoid rubocop EmptyBlock
        end
      end

      describe "#name" do
        it "returns the default name when name is not configured" do
          expect(subject.name).to eq("entraid")
        end
      end

      describe "#name=" do
        it "sets the name with correctly formatted name" do
          subject.name = "correct"
          expect(subject.name).to eq("correct")
        end

        it "raises an InvalidTenantName when the name contains invalid characters" do
          expect { subject.name = "name with spaces" }.to raise_error(Decidim::EntraID::InvalidTenantName)
          expect { subject.name = "Name_With_Capitalization" }.to raise_error(Decidim::EntraID::InvalidTenantName)
          expect { subject.name = "name-with-dashes" }.to raise_error(Decidim::EntraID::InvalidTenantName)
          expect { subject.name = "name_with_number_123" }.to raise_error(Decidim::EntraID::InvalidTenantName)
        end
      end

      describe "#authenticator_for" do
        let(:organization) { double }
        let(:oauth_hash) { double }
        let(:strategy) { double }

        it "initializes a new instance of the default authenticator class" do
          expect(Decidim::EntraID::Authentication::Authenticator).to receive(
            :new
          ).with(instance_of(described_class), organization, oauth_hash, strategy)

          subject.authenticator_for(organization, oauth_hash, strategy)
        end

        context "when authenticator class is configured" do
          let(:authenticator_class) { double }

          it "initializes a new instance of the configured class" do
            expect(authenticator_class).to receive(:new).with(
              instance_of(described_class),
              organization,
              oauth_hash,
              strategy
            )

            subject.authenticator_class = authenticator_class
            subject.authenticator_for(organization, oauth_hash, strategy)
          end
        end
      end

      describe "#metadata_collector_for" do
        let(:user_attributes) { double }
        let(:strategy) { double }

        it "initializes a new instance of the default authenticator class" do
          expect(Decidim::EntraID::Verification::MetadataCollector).to receive(
            :new
          ).with(instance_of(described_class), user_attributes, strategy)

          subject.metadata_collector_for(user_attributes, strategy)
        end

        context "when authenticator class is configured" do
          let(:metadata_collector_class) { double }

          it "initializes a new instance of the configured class" do
            expect(metadata_collector_class).to receive(:new).with(
              instance_of(described_class),
              user_attributes,
              strategy
            )

            subject.metadata_collector_class = metadata_collector_class
            subject.metadata_collector_for(user_attributes, strategy)
          end
        end
      end
    end
  end
end
