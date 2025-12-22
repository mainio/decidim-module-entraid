# frozen_string_literal: true

cert_file = Rails.application.secrets.omniauth.dig(:entraid, :certificate_file)
pkey_file = Rails.application.secrets.omniauth.dig(:entraid, :private_key_file)

if cert_file && File.exist?(cert_file) && pkey_file && File.exist?(pkey_file)
  Decidim::EntraID.configure do |config|
    # Define the name for the tenant. Only lowercase characters and underscores
    # are allowed. If you only have a single tenant, you do not need to
    # configure its name. When not configured, it will default to "entraid".
    # When you want to connect to multiple tenants, you will need to define a
    # unique name for each tenant.
    # config.name = "entraid"

    # You will get these from the Entra admin center.
    config.client_id = Rails.application.secrets.omniauth.dig(:entraid, :client_id)
    config.tenant_id = Rails.application.secrets.omniauth.dig(:entraid, :tenant_id)

    # Please generate a certificate for your application and upload the public
    # part (certificate file) to the Entra ID configuration center.
    #
    # This integration only supports certificate based authentication because
    # using a secret is not recommended for production use.
    config.certificate_file = cert_file
    config.private_key_file = pkey_file

    # Enable automatically assigned emails (if email is not validated).
    # config.auto_email_domain = "example.org"

    # Subscribe new users automatically to newsletters (default false).
    #
    # IMPORANT NOTE:
    # Legally it should be always a user's own decision if the want to subscribe
    # to any newsletters or not. Before enabling this, make sure you have your
    # legal basis covered for enabling it. E.g. for internal instances within
    # organizations, it should be generally acceptable but please confirm that
    # from the legal department first!
    # config.registration_newsletter_subscriptions = true
  end
end
