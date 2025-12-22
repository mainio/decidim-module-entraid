# frozen_string_literal: true

require "decidim/dev"
require "omniauth/entraid/test"
require "webmock"

require "decidim/entraid/test/data"
require "decidim/entraid/test/runtime"
require "decidim/entraid/test/oidc_server"
require "decidim/entraid/test/msgraph_api"

ENV["ENGINE_ROOT"] = File.dirname(__dir__)

Decidim::Dev.dummy_app_path = File.expand_path(File.join(__dir__, "decidim_dummy_app"))

Decidim::EntraID::Test::Runtime.initializer do
  # Silence the OmniAuth logger
  OmniAuth.config.logger = Logger.new("/dev/null")

  certgen = OmniAuth::EntraID::Test::CertificateGenerator.new
  pkey1 = certgen.private_key
  pkey2 = certgen.private_key

  # Configure the EntraID module with two tenants
  Decidim::EntraID.configure do |config|
    # Using default name: "entraid"
    config.client_id = "00001111-aaaa-2222-bbbb-3333cccc4444"
    config.tenant_id = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
    config.certificate = certgen.certificate_for(pkey1)
    config.private_key = pkey1
    config.metadata_attributes = {
      display_name: "display_name",
      given_name: "given_name",
      surname: "surname",
      principal_name: "user_principal_name"
    }
  end
  Decidim::EntraID.configure do |config|
    config.name = "other"
    config.client_id = "11112222-bbbb-3333-cccc-4444dddd5555"
    config.tenant_id = "bbbbcccc-1111-dddd-2222-eeee3333ffff"
    config.certificate = certgen.certificate_for(pkey2)
    config.private_key = pkey2
  end
end

# Note that the initializer needs to be registered before this file is required.
require "decidim/dev/test/base_spec_helper"

# Add the test templates path to ActionMailer
ActionMailer::Base.prepend_view_path(
  File.expand_path(File.join(__dir__, "fixtures", "mailer_templates"))
)

RSpec.configure do |config|
  # Make it possible to sign in and sign out the user in the request type specs.
  # This is needed because we need the request type spec for the omniauth
  # callback tests.
  config.include Devise::Test::IntegrationHelpers, type: :request
end
