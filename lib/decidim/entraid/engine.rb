# frozen_string_literal: true

# Define a non-standard ActiveSupport acronym for autoloading support.
ActiveSupport::Inflector.inflections do |inflect|
  inflect.acronym "EntraID"
end

module Decidim
  module EntraID
    class Engine < ::Rails::Engine
      isolate_namespace Decidim::EntraID

      routes do
        devise_scope :user do
          # Manually map the sign out path in order to control the sign out flow
          # through OmniAuth when the user signs out from the service. In these
          # cases, the user needs to be also signed out from the AD federation
          # server which is handled by the OmniAuth strategy.
          match(
            "/users/sign_out",
            to: "sessions#destroy",
            as: "destroy_user_session",
            via: [:delete, :post]
          )
        end
      end

      initializer "decidim_entraid.mount_routes", before: :add_routing_paths do
        # Mount the engine routes to Decidim::Core::Engine because otherwise
        # they would not get mounted properly. The EntraID engine needs to be
        # the very first engine to load in order to pass the sign in callback
        # routes to the module controllers instead of Decidim's own. Decidim
        # also provides the `Decidim.register_global_engine` method but these
        # are loaded too late in order to match the target routes correctly.
        Decidim::Core::Engine.routes.prepend do
          mount Decidim::EntraID::Engine => "/"
        end
      end

      initializer "decidim_entraid.setup", before: "devise.omniauth" do
        Decidim::EntraID.setup!
      end

      initializer "decidim_entraid.mail_interceptors" do
        ActionMailer::Base.register_interceptor(
          MailInterceptors::GeneratedRecipientsInterceptor
        )
      end
    end
  end
end
