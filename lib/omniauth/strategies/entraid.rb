# frozen_string_literal: true

require "net/http"
require "omniauth-oauth2"

module OmniAuth
  module Strategies
    # Omniauth strategy to login users through Microsoft Entra ID OAuth2
    # endpoints.
    #
    # Implements the OIDC flows with the following exceptions:
    # - Does not implement the discovery phase as the endpoints are known in
    #   advance.
    # - Instead of requesting the user info from the OIDC userinfo endpoint,
    #   utilizes the Microsoft Graph `/me` endpoint to fetch the necessary user
    #   information.
    #
    # This strategy is inspired by these two MIT licensed software with some
    # modifications:
    # https://github.com/pond/omniauth-entra-id
    # https://github.com/microsoftgraph/msgraph-sample-rubyrailsapp
    #
    # This implementation is better integrated into the target application
    # (Decidim) and provides some extra features compared to those, such as a
    # proper token validation with the JWKs available from Microsoft and OIDC
    # logout flow for improved security of users.
    class EntraID < OmniAuth::Strategies::OAuth2
      BASE_URL = "https://login.microsoftonline.com"
      GRAPH_API_URL = "https://graph.microsoft.com"
      DEFAULT_USER_PROPERTIES = %w(displayName givenName surname mail userPrincipalName).freeze

      option :name, :entraid

      option :jwt_leeway, 60

      option :tenant_id, nil

      option :domain_hint, nil

      option :certificate, nil
      option :private_key, nil

      # Additional layer of security, recommended current best practice even for
      # confidential clients, such as this application.
      option :pcke, true

      # Allows to fetch extra user properties through the Graph API call.
      option :extra_user_properties, nil

      # Unique ID for the user
      uid do
        # This needs to be included in the logout request, store it within the
        # session. Note that it needs to be specifically enabled as per
        # installation instructions.
        session["omniauth-entraid.login_hint"] = id_token_claims["login_hint"]

        # OID alone might not be unique; TID must be included. An alternative
        # would be to use 'sub' but this is only unique in client/app
        # registration context. If a different app registration is used, the
        # 'sub' values can be different too...
        #
        # https://learn.microsoft.com/en-us/entra/identity-platform/migrate-off-email-claim-authorization
        #
        # NB: If the TID is missing or blank the UID uses only the OID.
        [
          id_token_claims["tid"],
          id_token_claims["oid"]
        ].join(".")
      end

      info do
        # Note that the keys in the returned data are converted into snake_case
        # format by the `oauth2` gem.
        {
          name: raw_info["display_name"],
          email: raw_info["mail"],
          first_name: raw_info["given_name"],
          last_name: raw_info["surname"]
        }
      end

      # Contains all the raw info from the Microsoft Graph API response.
      extra do
        { raw_info: }
      end

      def client
        options.client_options.site = BASE_URL
        options.authorize_params.domain_hint = options.domain_hint if options.domain_hint
        options.authorize_params.prompt = request.params["prompt"] if defined?(request) && request.params["prompt"]

        options.token_params = {
          tenant: options.tenant_id,
          client_id: options.client_id,
          client_assertion:,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        }

        endpoint_url = "#{BASE_URL}/#{options.tenant_id}/oauth2/v2.0"
        options.client_options.authorize_url = "#{endpoint_url}/authorize"
        options.client_options.token_url = "#{endpoint_url}/token"

        # The auth scheme can be also other but as specified by the MS docs, use
        # request body. This is how the client_id is passed on to the token
        # endpoint. See:
        # https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#request-an-access-token-with-a-certificate-credential
        options.client_options.auth_scheme = :request_body

        super
      end

      # This is called during the callback phase when generating the unique ID
      # (uid) for the user. In case the ID token is invalid, this will fail with
      # an exception that fails the login attempt.
      #
      # Claims reference:
      # https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
      def id_token_claims
        @id_token_claims ||= begin
          token_data = begin
            ::JWT.decode(
              access_token.params["id_token"],
              nil,
              true,
              algorithms: signature_algoritms,
              jwks: signature_jwks
            ).first
          rescue ::JWT::DecodeError
            raise SignatureError, "Invalid signature for the ID token."
          rescue StandardError
            {}
          end

          validate_id_token!(token_data)

          token_data
        end
      end

      def raw_info
        @raw_info ||= begin
          # For the Graph API, see:
          # https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
          # https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
          props = DEFAULT_USER_PROPERTIES
          props += options[:extra_user_properties] if options[:extra_user_properties].is_a?(Array)

          access_token.get("#{GRAPH_API_URL}/v1.0/me?$select=#{props.join(",")}").parsed
        end
      rescue ::OAuth2::Error => e
        raise GraphApiError, e
      end

      def authorize_params
        super.tap do |params|
          params[:scope] = "openid profile email user.read"

          # As the identity server implements OIDC protocol, we add the nonce
          # parameter also to the request preventing ID token replay attacks.
          # This is also validated when the ID token is received (see the
          # validate_id_token! method).
          params[:nonce] = new_nonce
        end
      end

      def callback_phase
        super
      rescue ::OAuth2::TimeoutError => e
        # The parent strategy is catching another error.
        fail!(:timeout, e)
      rescue ::OAuth2::ConnectionError => e
        # The parent strategy is catching another error.
        fail!(:failed_to_connect, e)
      rescue GraphApiError => e
        fail!(:invalid_api_token, e)
      end

      # This would normally return the full URL with any URL params which would
      # cause a validation error at the other end.
      def callback_url
        options[:redirect_uri] || (full_host + callback_path)
      end

      def other_phase
        if on_subpath?(:logout)
          # At this stage, the application should have already handled the
          # actual session ending for the user and now we are only finalizing
          # the session by sending the user through the OIDC logout flow at
          # Entra.
          login_hint = session.delete("omniauth-entraid.login_hint")
          post_logout_path = session.delete("omniauth-entraid.post_logout_path")

          redirect logout_url(post_logout_path, login_hint)
        else
          call_app!
        end
      end

      private

      # Validates the ID token according to the following documentation:
      # https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens#validate-tokens
      #
      # Timestamps: the iat, nbf, and exp timestamps should all fall before or after the current time, as appropriate.
      # Audience: the aud claim should match the app ID for your application.
      # Nonce: the nonce claim in the payload must match the nonce parameter passed into the /authorize endpoint during the initial request.
      def validate_id_token!(token_data)
        issuer = "#{BASE_URL}/#{options.tenant_id}/v2.0"

        verify_params = {
          iss: issuer,
          aud: options.client_id,
          iat: { leeway: options.jwt_leeway },
          nbf: { leeway: options.jwt_leeway },
          exp: { leeway: options.jwt_leeway }
        }

        ::JWT::Claims.verify_payload!(token_data, verify_params)

        # Validate OIDC nonce parameter, not available as JWT claim verifier.
        raise InvalidNonceError, "Invalid nonce" if token_data["nonce"] != stored_nonce

        true
      end

      def new_nonce
        session["omniauth-entraid.nonce"] = SecureRandom.hex(16)
      end

      def stored_nonce
        session.delete("omniauth-entraid.nonce")
      end

      def on_subpath?(subpath)
        on_path?("#{request_path}/#{subpath}")
      end

      def client_assertion
        certificate_thumbprint = Digest::SHA1.digest(options.certificate.to_der)

        current_time = Time.now.to_i
        claims = {
          "aud" => "https://login.microsoftonline.com/#{options.tenant_id}/oauth2/v2.0/token",
          "exp" => current_time + 300,
          "iss" => options.client_id,
          "jti" => SecureRandom.uuid,
          "nbf" => current_time,
          "sub" => options.client_id,
          "iat" => current_time
        }
        x5c = Base64.strict_encode64(options.certificate.to_der)
        x5t = Base64.strict_encode64(certificate_thumbprint)

        JWT.encode(claims, options.private_key, "RS256", { "x5c": [x5c], "x5t": x5t })
      end

      def signature_jwks
        @signature_jwks ||= begin
          keys_url = "https://login.microsoftonline.com/#{options.tenant_id}/discovery/v2.0/keys"
          response = Net::HTTP.get_response(URI.parse(keys_url))
          raise SignatureKeyError, "Unexpected response from the keys endpoint." unless response.is_a?(Net::HTTPSuccess)

          json = JSON.parse(response.body)
          set =
            if json.has_key?("keys")
              JWT::JWK::Set.new(json["keys"])
            else
              # Assume a single key
              JWT::JWK::Set.new([json])
            end

          set.filter { |key| key[:use] == "sig" }
        end
      end

      # Algorithms defined at:
      # https://login.microsoftonline.com/{tenant_id}/.well-known/openid-configuration
      def signature_algoritms
        @signature_algoritms ||= %w(RS256).freeze
      end

      # This method is called from within the app so that the app can end the
      # session for the user properly before passing them to the entra logout
      # flow.
      #
      # https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/sign-out-of-openid-connect-oauth2-applications-without-user-selection-prompt
      def logout_url(post_logout_path = nil, logout_hint = nil)
        redirect_uri =
          if post_logout_path
            post_logout_path = "/#{post_logout_path}" unless post_logout_path.start_with?("/")
            "#{full_host}#{post_logout_path}"
          end

        logout_params = { post_logout_redirect_uri: redirect_uri, logout_hint: }

        endpoint_url = "#{BASE_URL}/#{options.tenant_id}/oauth2/v2.0/logout"
        logout_uri = URI.parse(endpoint_url)
        logout_uri.query = logout_params.compact_blank.map do |(key, val)|
          "#{key}=#{Rack::Utils.escape(val)}"
        end.join("&")

        logout_uri.to_s
      end

      class GraphApiError < StandardError
        attr_reader :oauth_error

        def initialize(oauth_error)
          @oauth_error = oauth_error
          super(oauth_error.message)
        end
      end

      class InvalidNonceError < StandardError; end

      class SignatureError < StandardError; end

      class SignatureKeyError < StandardError; end
    end
  end
end

OmniAuth.config.add_camelization "entraid", "EntraID"
