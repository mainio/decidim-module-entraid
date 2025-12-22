# frozen_string_literal: true

module Decidim
  module EntraID
    class SessionsController < ::Decidim::Devise::SessionsController
      def destroy
        # Unless the user is signed in through the AD federation server,
        # continue normally.
        return super unless session.delete("decidim-entraid.signed_in")

        # If the user is signed in through AD federation server, redirect them
        # through.
        tenant_name = session.delete("decidim-entraid.tenant")
        tenant = Decidim::EntraID.tenants.find { |t| t.name == tenant_name }
        raise "Unkown Entra ID tenant: #{tenant_name}" unless tenant

        # These session variables get destroyed along with the user's active
        # session. They are needed for the logout request. The login hint is
        # needed for the external logout request.
        login_hint = session.delete("omniauth-entraid.login_hint")
        post_logout_path = logout_return_path

        # End the local user session.
        current_user.invalidate_all_sessions!
        signed_out = (::Devise.sign_out_all_scopes ? sign_out : sign_out(resource_name))

        # Set the notice flash message to be displayed.
        store_logout_message(signed_out)

        # Pass the login hint to the next OmniAuth request after the session is
        # cleared.
        session["omniauth-entraid.login_hint"] = login_hint if login_hint
        session["omniauth-entraid.post_logout_path"] = post_logout_path

        # Individual sign out path for each tenant to pass it to correct
        # OmniAuth handler.
        sign_out_path = send("user_#{tenant.name}_omniauth_logout_path")
        sign_out_path += "?success=1" if signed_out

        redirect_to sign_out_path
      end

      # The service logout should redirect the user to perform the logout at
      # entra (handled by OmniAuth).
      def logout
        # This is handled already by OmniAuth
        redirect_to decidim.root_path
      end

      # Front channel logout is initiated by the user logging out through Entra
      # in which case the session needs to be ended on this platform at the same
      # time as the user is logged out from other services. The logout requests
      # are wrapped within an iframe element on the Entra logout page which does
      # a request to all services with active sessions.
      #
      # Note that this is NOT handled by the OmniAuth provider since we need to
      # sign the user out within the context of the application.
      def front_channel_logout
        return render plain: "" unless user_signed_in?

        current_user.invalidate_all_sessions!
        signed_out = (::Devise.sign_out_all_scopes ? sign_out : sign_out(resource_name))

        store_logout_message(signed_out)

        render plain: "Signed out."
      end

      private

      def logout_return_path
        path = after_sign_out_path_for(current_user)
        if path
          # Ensure it is a path
          uri = URI.parse(path)
          uri.path
        else
          "/"
        end
      end

      def store_logout_message(_success)
        suffix = params[:translation_suffix]
        if suffix == "timed_out"
          set_flash_message! :notice, suffix, { scope: "decidim.devise.sessions" }
        else
          set_flash_message! :notice, :signed_out
        end
      end
    end
  end
end
