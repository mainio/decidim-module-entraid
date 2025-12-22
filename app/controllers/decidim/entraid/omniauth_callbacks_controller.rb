# frozen_string_literal: true

module Decidim
  module EntraID
    class OmniauthCallbacksController < ::Decidim::Devise::OmniauthRegistrationsController
      # Make the view helpers available needed in the views
      helper Decidim::EntraID::Engine.routes.url_helpers
      helper_method :omniauth_registrations_path

      skip_before_action :verify_authenticity_token, only: [:entraid, :failure]
      skip_after_action :verify_same_origin_request, only: [:entraid, :failure]

      # This is called always after the user returns from the authentication
      # flow from the Entra ID identity provider.
      def entraid
        session["decidim-entraid.signed_in"] = true
        session["decidim-entraid.tenant"] = tenant.name

        authenticator.validate!

        if user_signed_in?
          # The user is most likely returning from an authorization request
          # because they are already signed in. In this case, add the
          # authorization and redirect the user back to the authorizations view.

          # Make sure the user has an identity created in order to aid future
          # Entra ID sign ins. In case this fails, it will raise a
          # Decidim::EntraID::Authentication::IdentityBoundToOtherUserError
          # which is handled below.
          authenticator.identify_user!(current_user)

          # Add the authorization for the user
          return fail_authorize unless authorize_user(current_user)

          # Make sure the user details are up to date
          authenticator.update_user!(current_user)

          # Show the success message and redirect back to the authorizations
          flash[:notice] = t(
            "authorizations.create.success",
            scope: "decidim.entraid.verification"
          )
          return redirect_to(
            stored_location_for(resource || :user) ||
            decidim.root_path
          )
        end

        # Normal authentication request, proceed with Decidim's internal logic.
        send(:create)
      rescue Decidim::EntraID::Authentication::ValidationError => e
        fail_authorize(e.validation_key)
      rescue Decidim::EntraID::Authentication::IdentityBoundToOtherUserError
        fail_authorize(:identity_bound_to_other_user)
      end

      def failure
        strategy = failed_strategy
        return super unless strategy

        flash[:alert] = failure_message
        redirect_to after_omniauth_failure_path_for(resource_name)
      end

      # This is overridden method from the Devise controller helpers
      # This is called when the user is successfully authenticated which means
      # that we also need to add the authorization for the user automatically
      # because a succesful Active Directory authentication means the user has
      # been successfully authorized as well.
      def sign_in_and_redirect(resource_or_scope, *args)
        # Add authorization for the user
        if resource_or_scope.is_a?(::Decidim::User)
          return fail_authorize unless authorize_user(resource_or_scope)

          # Make sure the user details are up to date
          authenticator.update_user!(resource_or_scope)
        end

        super
      end

      # Disable authorization redirect for the first login
      def first_login_and_not_authorized?(_user)
        false
      end

      private

      def authorize_user(user)
        authenticator.authorize_user!(user)
      rescue Decidim::EntraID::Authentication::AuthorizationBoundToOtherUserError
        nil
      end

      def fail_authorize(failure_message_key = :already_authorized)
        flash[:alert] = t(
          "failure.#{failure_message_key}",
          scope: "decidim.#{tenant.name}.omniauth_callbacks"
        )

        redirect_path = stored_location_for(resource || :user) || decidim.root_path
        if session.delete("decidim-entraid.signed_in")
          tenant = session.delete("decidim-entraid.tenant")
          sign_out_path = send("user_#{tenant}_omniauth_logout_path")

          return redirect_to sign_out_path
        end

        redirect_to redirect_path
      end

      def failure_message
        error_type = request.env["omniauth.error.type"]
        return super unless error_type.is_a?(Symbol)

        # Known errors:
        # - invalid_credentials
        # - timeout
        # - failed_to_connect
        # - csrf_detected
        # - invalid_api_token
        i18n_scope = "decidim.entraid.omniauth_callbacks.failure"
        return super unless I18n.exists?(error_type, scope: i18n_scope)

        t(error_type, scope: i18n_scope)
      end

      # Needs to be specifically defined because the core engine routes are not
      # all properly loaded for the view and this helper method is needed for
      # defining the omniauth registration form's submit path.
      def omniauth_registrations_path(resource)
        Decidim::Core::Engine.routes.url_helpers.omniauth_registrations_path(resource)
      end

      # Private: Create form params from omniauth hash
      # Since we are using trusted omniauth data we are generating a valid signature.
      def user_params_from_oauth_hash
        authenticator.user_params_from_oauth_hash
      end

      def authenticator
        @authenticator ||= tenant.authenticator_for(
          current_organization,
          oauth_hash,
          request.env["omniauth.strategy"]
        )
      end

      def tenant
        @tenant ||= begin
          matches = request.path.match(%r{\A/users/auth/([^/]+)/.+})
          raise "Invalid Entra ID tenant" unless matches

          name = matches[1]
          tenant = Decidim::EntraID.tenants.find { |t| t.name == name }
          raise "Unkown Entra ID tenant: #{name}" unless tenant

          tenant
        end
      end

      def verified_email
        authenticator.verified_email
      end
    end
  end
end
