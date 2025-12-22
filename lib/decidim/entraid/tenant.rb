# frozen_string_literal: true

module Decidim
  module EntraID
    class Tenant
      include ActiveSupport::Configurable

      # Individual name for the tenant. Not relevant if you only configure a
      # single tenant, the default name "entraid" is sufficient in that case. If
      # you have multiple tenants, use an individual name for each tenant, e.g.
      # "acmeinc" and "eduorg".
      #
      # The name can only contain lowercase characters and underscores.
      config_accessor :name, instance_writer: false do
        "entraid"
      end

      # Defines the auto email domain to generate verified email addresses upon
      # the user's registration automatically that have format similar to
      # "entraid-identifier@auto-email-domain.fi".
      #
      # In case this is not defined, the default is the organization's domain.
      config_accessor :auto_email_domain

      # The client ID used to connect to the Microsoft APIs.
      config_accessor :client_id

      # The tenant ID that is used as the underlying user directory.
      config_accessor :tenant_id

      # The certificate string for the application
      config_accessor :certificate, instance_reader: false

      # The private key string for the application
      config_accessor :private_key, instance_reader: false

      # The certificate file for the application
      config_accessor :certificate_file

      # The private key file for the application
      config_accessor :private_key_file

      # These are extra attributes that can be stored for the authorization
      # metadata. Define these as follows:
      #
      # Decidim::EntraID.configure do |config|
      #   # ...
      #   config.metadata_attributes = {
      #     employee_id: "employee_id",
      #     department: "department"
      #   }
      # end
      #
      # The key in the array defines the attribute name in the Decidim
      # authorization properties. The value defines the property name in the
      # Microsoft Graph API in the underscored format, e.g. "employeeId" becomes
      # "employee_id".
      #
      # The corresponding extra attributes are defined at the following
      # documentation:
      # https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
      #
      # Note that you need to add any extra attributes to the user attributes
      # query through the `extra_user_properties` configuration (see below).
      config_accessor :metadata_attributes do
        {}
      end

      # Extra user properties to retrieve from the Graph API
      #
      # Available properties defined at:
      # https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
      #
      # Define the configuration as an array of strings corresponding to the
      # available properties.
      #
      # Example:
      #
      # Decidim::EntraID.configure do |config|
      #   # ...
      #   config.extra_user_properties = %w(employeeId)
      # end
      config_accessor :extra_user_properties do
        nil
      end

      # Defines whether registered users are automatically subscribed to the
      # newsletters during the OmniAuth registration flow. This is only updated
      # during the first login, so users can still unsubscribe if they later
      # decide they don't want to receive the newsletter and later logins will not
      # change the subscription state.
      config_accessor :registration_newsletter_subscriptions do
        false
      end

      # Allows customizing the authorization workflow e.g. for adding custom
      # workflow options or configuring an action authorizer for the
      # particular needs.
      config_accessor :workflow_configurator do
        lambda do |workflow|
          # By default, expiration is set to 0 minutes which means it will
          # never expire.
          workflow.expires_in = 0.minutes
        end
      end

      # Allows customizing parts of the authentication flow such as validating
      # the authorization data before allowing the user to be authenticated.
      config_accessor :authenticator_class do
        Decidim::EntraID::Authentication::Authenticator
      end

      # Allows customizing how the authorization metadata gets collected from
      # the attributes passed from the authorization endpoint.
      config_accessor :metadata_collector_class do
        Decidim::EntraID::Verification::MetadataCollector
      end

      def initialize
        yield self
      end

      def name=(name)
        unless name.match?(/^[a-z_]+$/)
          raise(
            InvalidTenantName,
            "The Entra ID tenant name can only contain lowercase letters and underscores."
          )
        end
        config.name = name
      end

      def authenticator_for(organization, oauth_hash, oauth_strategy)
        authenticator_class.new(self, organization, oauth_hash, oauth_strategy)
      end

      def metadata_collector_for(attributes, oauth_strategy)
        metadata_collector_class.new(self, attributes, oauth_strategy)
      end

      def certificate
        @certificate ||= begin
          cert_content =
            if certificate_file
              File.read(certificate_file)
            else
              config.certificate
            end
          if cert_content.is_a?(OpenSSL::X509::Certificate)
            cert_content
          else
            OpenSSL::X509::Certificate.new(cert_content)
          end
        end
      end

      def private_key
        @private_key ||= begin
          pkey_content =
            if private_key_file
              File.read(private_key_file)
            else
              config.private_key
            end
          if pkey_content.is_a?(OpenSSL::PKey::RSA)
            pkey_content
          else
            OpenSSL::PKey::RSA.new(pkey_content)
          end
        end
      end

      def omniauth_settings
        {
          name:,
          strategy_class: OmniAuth::Strategies::EntraID,
          client_id:,
          tenant_id:,
          certificate:,
          private_key:,
          extra_user_properties:
        }
      end

      def setup!
        setup_routes!

        # Configure the OmniAuth strategy for Devise
        ::Devise.setup do |config|
          config.omniauth(name.to_sym, omniauth_settings)
        end

        # Customized version of Devise's OmniAuth failure app in order to handle
        # the failures properly. Without this, the failure requests would end
        # up in an ActionController::InvalidAuthenticityToken exception.
        devise_failure_app = OmniAuth.config.on_failure
        OmniAuth.config.on_failure = proc do |env|
          if env["PATH_INFO"] && env["PATH_INFO"].match?(%r{\A/users/auth/#{config.name}(\z|/.+)})
            env["devise.mapping"] = ::Devise.mappings[:user]
            Decidim::EntraID::OmniauthCallbacksController.action(:failure).call(env)
          else
            # Call the default for others.
            devise_failure_app.call(env)
          end
        end
      end

      def setup_routes!
        # This assignment makes the config variable accessible in the block
        # below.
        config = self.config
        Decidim::EntraID::Engine.routes do
          devise_scope :user do
            # Manually map the user omniauth routes for Devise because the
            # default routes are mounted by core Decidim. This is because we
            # want to map these routes to the local callbacks controller instead
            # of the Decidim core.
            #
            # See:
            # https://github.com/heartcombo/devise/blob/9aa17eec07719a97385dd40fa05c4029983a1cd5/lib/devise/rails/routes.rb#L446-L456
            match(
              "/users/auth/#{config.name}",
              to: "omniauth_callbacks#passthru",
              as: "user_#{config.name}_omniauth_authorize",
              via: [:get, :post]
            )

            match(
              "/users/auth/#{config.name}/callback",
              to: "omniauth_callbacks#entraid",
              as: "user_#{config.name}_omniauth_callback",
              via: [:get]
            )

            # Add the logout and front channel logout paths to be able to pass
            # these requests to OmniAuth.
            match(
              "/users/auth/#{config.name}/logout",
              to: "sessions#logout",
              as: "user_#{config.name}_omniauth_logout",
              via: [:get, :post]
            )

            match(
              "/users/auth/#{config.name}/fclogout",
              to: "sessions#front_channel_logout",
              as: "user_#{config.name}_omniauth_front_channel_logout",
              via: [:get, :post]
            )
          end
        end
      end

      def auto_email_for(organization, identifier_digest)
        domain = auto_email_domain || organization.host
        "#{name}-#{identifier_digest}@#{domain}"
      end

      def auto_email_matches?(email)
        return false unless auto_email_domain

        email =~ /^#{name}-[a-z0-9]{32}@#{auto_email_domain}$/
      end

      # Used to determine the default service provider entity ID in case not
      # specifically set by the `sp_entity_id` configuration option.
      def application_host
        url_options = application_url_options

        # Note that at least Azure AD requires all callback URLs to be HTTPS, so
        # we'll default to that.
        host = url_options[:host]
        port = url_options[:port]
        protocol = url_options[:protocol]
        protocol = port.to_i == 80 ? "http" : "https" if protocol.blank?
        if host.blank?
          # Default to local development environment.
          host = "localhost"
          port ||= 3000
        end

        return "#{protocol}://#{host}:#{port}" if port && [80, 443].exclude?(port.to_i)

        "#{protocol}://#{host}"
      end

      def application_url_options
        conf = Rails.application.config
        url_options = conf.action_controller.default_url_options
        url_options = conf.action_mailer.default_url_options if !url_options || !url_options[:host]
        url_options || {}
      end
    end
  end
end
