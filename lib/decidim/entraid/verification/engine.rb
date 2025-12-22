# frozen_string_literal: true

module Decidim
  module EntraID
    module Verification
      # This is an engine that performs user authorization.
      class Engine < ::Rails::Engine
        isolate_namespace Decidim::EntraID::Verification

        paths["db/migrate"] = nil
        paths["lib/tasks"] = nil

        routes do
          resource :authorizations, only: [:new], as: :authorization

          root to: "authorizations#new"
        end

        initializer "decidim_entraid.verification_workflow", after: :load_config_initializers do
          Decidim::EntraID.tenants.each do |tenant|
            # We cannot use the same name as the tenant for the verification
            # workflow because otherwise the route namespace (e.g.
            # "decidim_entraid") would conflict with the main engine controlling
            # the authentication flows. The main problem that this would bring
            # is that the root path for this engine would not be found.
            Decidim::Verifications.register_workflow(:"#{tenant.name}_identity") do |workflow|
              workflow.engine = Decidim::EntraID::Verification::Engine

              tenant.workflow_configurator.call(workflow)
            end
          end
        end

        def load_seed
          Decidim::EntraID.tenants.each do |tenant|
            # Enable the authorizations for each tenant
            org = Decidim::Organization.first
            org.available_authorizations << :"#{tenant.name}_identity"
            org.save!
          end
        end
      end
    end
  end
end
