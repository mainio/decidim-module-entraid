# frozen_string_literal: true

module Decidim
  module EntraID
    module Verification
      class MetadataCollector
        def initialize(tenant, user_attributes, oauth_strategy)
          @tenant = tenant
          @user_attributes = user_attributes
          @oauth_strategy = oauth_strategy
        end

        def metadata
          return nil unless tenant.metadata_attributes.is_a?(Hash)
          return nil if tenant.metadata_attributes.blank?

          collect.compact
        end

        protected

        attr_reader :tenant, :user_attributes, :oauth_strategy

        def collect
          tenant.metadata_attributes.transform_values do |entra_attribute|
            user_attributes[entra_attribute]
          end
        end
      end
    end
  end
end
