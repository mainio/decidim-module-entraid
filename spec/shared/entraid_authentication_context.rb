# frozen_string_literal: true

shared_context "with EntraID authentication flow" do
  let(:entra_tenant) { Decidim::EntraID.tenants.first }
  let(:entra_oidc) { Decidim::EntraID::Test::OIDCServer.new(tenant_id: entra_tenant.tenant_id) }
  let(:entra_graphapi) { Decidim::EntraID::Test::MsgraphAPI.new(entra_oidc) }
  let(:entra_identity) { build(:entraid_identity) }
  let(:entra_token_response) do
    entra_oidc.generate_token_response(
      identity: entra_identity,
      client_id: entra_tenant.client_id,
      id_token_nonce: entra_token_nonce
    )
  end
  let(:entra_token_nonce) { session["omniauth-entraid.nonce"] }
  let(:entra_token_endpoint_stub) do
    stub_request(
      :post,
      "https://login.microsoftonline.com/#{entra_tenant.tenant_id}/oauth2/v2.0/token"
    ).to_return(
      status: 200,
      body: entra_token_response.to_json,
      headers: {
        "Content-Type" => "application/json"
      }
    )
  end
  let(:entra_jwks_endpoint_stub) do
    stub_request(
      :get,
      "https://login.microsoftonline.com/#{entra_tenant.tenant_id}/discovery/v2.0/keys"
    ).to_return(
      status: 200,
      body: entra_oidc.generate_jwks_response.to_json,
      headers: {
        "Content-Type" => "application/json"
      }
    )
  end
  let(:entra_graphapi_endpoint_stub) do
    stub_request(
      :get,
      "https://graph.microsoft.com/v1.0/me?$select=displayName,givenName,surname,mail,userPrincipalName"
    ).with(
      headers: { "Authorization" => "Bearer #{entra_token_response[:access_token]}" }
    ).to_return { |req| entra_graphapi.serve(req) }
  end

  def omniauth_callback(env: nil)
    post "/users/auth/entraid"

    entra_token_endpoint_stub
    entra_jwks_endpoint_stub
    entra_graphapi_endpoint_stub

    request_args = { env: }.compact
    callback_params = {
      code: entra_oidc.generate_authorization_code,
      state: session["omniauth.state"],
      session_state: SecureRandom.uuid
    }
    get "/users/auth/entraid/callback?#{callback_params.to_query}", **request_args
  end
end
