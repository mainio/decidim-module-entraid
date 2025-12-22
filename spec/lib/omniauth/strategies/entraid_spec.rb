# frozen_string_literal: true

require "spec_helper"
require "omniauth/strategies/entraid"

module OmniAuth
  describe Strategies::EntraID, type: :strategy do
    include Rack::Test::Methods
    include OmniAuth::Test::StrategyTestCase

    let!(:organization) { create(:organization, host: "example.org") }

    let(:certgen) { OmniAuth::EntraID::Test::CertificateGenerator.new }
    let(:private_key) { certgen.private_key }
    let(:certificate) { certgen.certificate_for(private_key) }
    let(:client_id) { "00001111-aaaa-2222-bbbb-3333cccc4444" }
    let(:tenant_id) { "aaaabbbb-0000-cccc-1111-dddd2222eeee" }
    let(:oidc) { Decidim::EntraID::Test::OIDCServer.new(tenant_id:) }
    let(:graphapi) { Decidim::EntraID::Test::MsgraphAPI.new(oidc) }

    let(:auth_hash) { last_request.env["omniauth.auth"] }
    let(:strategy_options) do
      {
        client_id:,
        tenant_id:,
        certificate:,
        private_key:
      }
    end
    let(:strategy) { [described_class, strategy_options] }
    let(:instance) { last_request.env["omniauth.strategy"] }
    let(:mock_warden) do
      warden = double
      allow(warden).to receive(:authenticate).and_return(nil)

      warden
    end

    before do
      current_session.env("warden", mock_warden)
      current_session.env("decidim.current_organization", organization)
    end

    describe "#client" do
      subject do
        post "/users/auth/entraid"
        instance.client
      end

      it "initializes the client with the correct options" do
        expect(subject.id).to eq(client_id)
        expect(subject.secret).to be_nil
        expect(subject.site).to eq("https://login.microsoftonline.com")
        expect(subject.options).to match(
          hash_including(
            authorize_url: "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/authorize",
            token_url: "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token",
            token_method: :post,
            auth_scheme: :request_body,
            access_token_class: ::OAuth2::AccessToken
          )
        )
      end
    end

    describe "POST /users/auth/entraid" do
      subject { post "/users/auth/entraid" }

      let(:redirect_uri) { URI.parse(subject.location) }
      let(:query) { Rack::Utils.parse_query(redirect_uri.query).symbolize_keys }

      before { subject }

      it "redirects the user to the authorize endpoint" do
        expect(subject).to be_redirect
        expect(redirect_uri.scheme).to eq("https")
        expect(redirect_uri.host).to eq("login.microsoftonline.com")
        expect(redirect_uri.path).to eq("/aaaabbbb-0000-cccc-1111-dddd2222eeee/oauth2/v2.0/authorize")
        expect(query).to match(
          client_id: "00001111-aaaa-2222-bbbb-3333cccc4444",
          nonce: an_instance_of(String),
          redirect_uri: "http://example.org/users/auth/entraid/callback",
          response_type: "code",
          scope: "openid profile email user.read",
          state: an_instance_of(String)
        )
        expect(query[:nonce]).to match(/\A[0-9a-f]{32}\z/)
        expect(query[:state]).to match(/\A[0-9a-f]{48}\z/)
      end

      it "stores the state in the session" do
        expect(session["omniauth.state"]).to match(/\A[0-9a-f]{48}\z/)
      end

      it "stores the nonce in the session" do
        expect(session["omniauth-entraid.nonce"]).to match(/\A[0-9a-f]{32}\z/)
      end
    end

    describe "GET /users/auth/entraid/callback" do
      subject do
        # First initiate the authentication request, this would redirect the
        # user to perform the authentication at the identity provider's end.
        post "/users/auth/entraid"

        # Stub the endpoints requested during the authentication callback
        token_endpoint_stub
        jwks_endpoint_stub
        graph_api_endpoint_stub

        # Send the GET request to the callback path as if the user was
        # redirected back to the app after a successful authentication.
        state = session["omniauth.state"]
        callback_params = {
          code: authorization_code,
          state:,
          session_state: SecureRandom.uuid
        }
        get "/users/auth/entraid/callback?#{callback_params.to_query}"
      end

      let(:token_endpoint_stub) do
        stub_request(
          :post,
          "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token"
        ).to_return(
          status: 200,
          body: token_response.to_json,
          headers: {
            "Content-Type" => "application/json"
          }
        )
      end
      let(:jwks_endpoint_stub) do
        stub_request(
          :get,
          "https://login.microsoftonline.com/#{tenant_id}/discovery/v2.0/keys"
        ).to_return(
          status: 200,
          body: oidc.generate_jwks_response.to_json,
          headers: {
            "Content-Type" => "application/json"
          }
        )
      end
      let(:graph_api_endpoint_stub) do
        stub_request(
          :get,
          "https://graph.microsoft.com/v1.0/me?$select=displayName,givenName,surname,mail,userPrincipalName"
        ).with(
          headers: { "Authorization" => "Bearer #{access_token}" }
        ).to_return { |req| graphapi.serve(req) }
      end

      let(:identity) { build(:entraid_identity) }
      let(:token_response) { oidc.generate_token_response(identity:, client_id:, id_token_nonce: session["omniauth-entraid.nonce"]) }
      let(:access_token) { token_response[:access_token] }
      let(:authorization_code) { oidc.generate_authorization_code }
      let(:app_response) { "Application undefined." }
      let(:redirect_uri) { URI.parse(subject.location) }

      before { subject }

      it "performs the full authentication flow and calls the application" do
        expect(subject).to have_http_status(:not_found)
        expect(subject.body).to eq(app_response)
      end

      it "returns the correct data in the user info" do
        expect(auth_hash.info.to_hash).to match(
          "name" => identity.name,
          "email" => identity.email,
          "first_name" => identity.given_name,
          "last_name" => identity.family_name
        )
      end

      it "returns the correct data in the extra info" do
        expect(auth_hash.extra.to_hash).to match(
          "raw_info" => {
            "@odata.context" => "https://graph.microsoft.com/v1.0/$metadata#users(displayName,givenName,surname,mail,userPrincipalName)/$entity",
            "display_name" => identity.name,
            "given_name" => identity.given_name,
            "surname" => identity.family_name,
            "mail" => identity.email,
            "user_principal_name" => identity.principal_name
          }
        )
      end

      context "when requesting the token" do
        subject { post "/users/auth/entraid" }

        it "generates a valid token request" do
          stub_request(
            :post,
            "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token"
          ).with do |request|
            expect(request.headers["Content-Type"]).to eq("application/x-www-form-urlencoded")

            params = Rack::Utils.parse_query(request.body).symbolize_keys
            expect(params[:client_assertion_type]).to eq("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            expect(params[:client_id]).to eq(client_id)
            expect(params[:code]).to eq(authorization_code)
            expect(params[:grant_type]).to eq("authorization_code")
            expect(params[:redirect_uri]).to eq("http://example.org/users/auth/entraid/callback")
            expect(params[:tenant]).to eq(tenant_id)

            # Validate the assertion
            assertion = params[:client_assertion]
            decoded_assertion = ::JWT.decode(assertion, certificate.public_key, true, { algorithm: "RS256" }).first
            expect(decoded_assertion).to match(
              "aud" => "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token",
              "exp" => an_instance_of(Integer),
              "iss" => client_id,
              "jti" => an_instance_of(String),
              "nbf" => an_instance_of(Integer),
              "sub" => client_id,
              "iat" => an_instance_of(Integer)
            )
            # Should match a random UUID format returned by `SecureRandom.uuid`.
            expect(decoded_assertion["jti"]).to match(/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/)
            expect(decoded_assertion["nbf"]).to be <= Time.current.to_i
            expect(decoded_assertion["iat"]).to be <= Time.current.to_i
            expect(decoded_assertion["exp"]).to eq(decoded_assertion["iat"] + 300)
          end.to_return(
            status: 200,
            body: token_response.to_json,
            headers: {
              "Content-Type" => "application/json"
            }
          )

          # Stub the keys response
          jwks_endpoint_stub

          # Stub the Graph API response
          graph_api_endpoint_stub

          # Send the GET request to the callback path as if the user was
          # redirected back to the app after a successful authentication.
          state = session["omniauth.state"]
          callback_params = {
            code: authorization_code,
            state:,
            session_state: SecureRandom.uuid
          }
          get "/users/auth/entraid/callback?#{callback_params.to_query}"
        end

        context "and the token request fails" do
          subject do
            post "/users/auth/entraid"

            # Typical response from the other end is HTTP 400 (Bad Request) in
            # case some of the parameters are wrong, such as the client assertion
            # or the auth code.
            stub_request(
              :post,
              "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token"
            ).to_return(
              status: 400,
              body: token_response.to_json,
              headers: {
                "Content-Type" => "application/json"
              }
            )

            # Make the failure app work correctly.
            allow(session).to receive(:enabled?).and_return(true)
            allow(session).to receive(:loaded?).and_return(true)

            state = session["omniauth.state"]
            callback_params = {
              code: authorization_code,
              state:,
              session_state: SecureRandom.uuid
            }
            get "/users/auth/entraid/callback?#{callback_params.to_query}"
          end

          let(:token_response) do
            trace_id = SecureRandom.uuid
            correlation_id = SecureRandom.uuid
            timestamp = Time.current.utc.iso8601.tr("T", " ")
            {
              error: "invalid_grant",
              error_description: "AADSTS9002313: Invalid request. Request is malformed or invalid. Trace ID: #{trace_id} Correlation ID: #{correlation_id} Timestamp: #{timestamp}",
              error_codes: [9_002_313],
              timestamp:,
              trace_id:,
              correlation_id:,
              error_uri: "https://login.microsoftonline.com/error?code=9002313"
            }
          end

          it "responds with a correct error message" do
            expect(subject).to be_redirect
            expect(redirect_uri.path).to eq("/users/sign_in")

            expect(instance.env["omniauth.error"]).to be_instance_of(::OAuth2::Error)
            expect(instance.env["omniauth.error.type"]).to eq(:invalid_credentials)
          end
        end
      end

      context "when the graph API request fails" do
        subject do
          post "/users/auth/entraid"

          stub_request(
            :post,
            "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/token"
          ).to_return(
            status: 200,
            body: token_response.to_json,
            headers: {
              "Content-Type" => "application/json"
            }
          )

          # Make the failure app work correctly.
          allow(session).to receive(:enabled?).and_return(true)
          allow(session).to receive(:loaded?).and_return(true)

          stub_request(
            :get,
            "https://graph.microsoft.com/v1.0/me?$select=displayName,givenName,surname,mail,userPrincipalName"
          ).to_return(
            status: 401,
            body: graphapi_response.to_json,
            headers: {
              "Content-Type" => "application/json"
            }
          )

          state = session["omniauth.state"]
          callback_params = {
            code: authorization_code,
            state:,
            session_state: SecureRandom.uuid
          }
          get "/users/auth/entraid/callback?#{callback_params.to_query}"
        end

        let(:graphapi_response) do
          request_id = SecureRandom.uuid
          {
            error: {
              code: "InvalidAuthenticationToken",
              message: "DX14100: JWT is not well formed, there are no dots (.).\nThe token needs to be in JWS or JWE Compact Serialization Format. (JWS): 'EncodedHeader.EncodedPayload.EncodedSignature'. (JWE): 'EncodedProtectedHeader.EncodedEncryptedKey.EncodedInitializationVector.EncodedCiphertext.EncodedAuthenticationTag'.",
              innerError: {
                "date" => Time.current.utc.iso8601.sub(/Z\z/, ""),
                "request-id" => request_id,
                "client-request-id" => request_id
              }
            }
          }
        end

        it "responds with a correct error message" do
          expect(subject).to be_redirect
          expect(redirect_uri.path).to eq("/users/sign_in")

          expect(instance.env["omniauth.error"]).to be_instance_of(described_class::GraphApiError)
          expect(instance.env["omniauth.error.type"]).to eq(:invalid_api_token)
        end
      end
    end

    describe "GET /users/auth/entraid/logout" do
      subject do
        # Initiate a session before calling the logout path
        get "/"

        session["omniauth-entraid.login_hint"] = login_hint if login_hint
        session["omniauth-entraid.post_logout_path"] = post_logout_path if post_logout_path

        # Call the logout path
        get "/users/auth/entraid/logout"
      end

      let(:login_hint) { SecureRandom.base64.sub(/=+\z/, "") }
      let(:post_logout_path) { "/return/to/path" }

      let(:redirect_uri) { URI.parse(subject.location) }
      let(:query) { Rack::Utils.parse_query(redirect_uri.query).symbolize_keys }

      it "redirects the user to the entra logout URL" do
        expect(subject).to be_redirect
        expect(redirect_uri.scheme).to eq("https")
        expect(redirect_uri.host).to eq("login.microsoftonline.com")
        expect(redirect_uri.path).to eq("/aaaabbbb-0000-cccc-1111-dddd2222eeee/oauth2/v2.0/logout")
        expect(query).to match(
          logout_hint: login_hint,
          post_logout_redirect_uri: "http://example.org#{post_logout_path}"
        )
      end

      context "without any parameters" do
        let(:login_hint) { nil }
        let(:post_logout_path) { nil }

        it "redirects without any parameters" do
          expect(subject).to be_redirect
          expect(query).to be_empty
        end
      end

      context "with only login hint" do
        let(:post_logout_path) { nil }

        it "redirects with correct parameters" do
          expect(subject).to be_redirect
          expect(query).to match(logout_hint: login_hint)
        end
      end
    end
  end
end
