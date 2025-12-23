# Decidim::EntraID - Integrate Decidim to Microsoft Entra ID

[![Build Status](https://github.com/mainio/decidim-module-entraid/actions/workflows/ci_entraid.yml/badge.svg)](https://github.com/mainio/decidim-module-entraid/actions)
[![codecov](https://codecov.io/gh/mainio/decidim-module-entraid/branch/main/graph/badge.svg)](https://codecov.io/gh/mainio/decidim-module-entraid)

A [Decidim](https://github.com/decidim/decidim) module to add Microsoft Entra ID
authentication to Decidim as a way to authenticate and authorize the users.

This module allows Decidim users to log in to Decidim using their organization's
Entra ID accounts, which are typically the same accounts they use to log in to
their computers. In addition, these users can also be authorized with the data
available through Entra ID (person's department, location, groups, etc.). This
uses the OAuth 2 endpoints provided by the OIDC server available at the Microsoft
Entra services.

In addition to the default OAuth 2 authentication capability with Entra ID, this
module provides the following functionality:

- Extra security features during the authorization flow
  * Validating the issued ID token signature against the keys reported by
    Entra ID
  * OICD nonce check against the issued ID token
  * PKCE during the authorization flow
- Connecting the service with multiple Entra ID tenants for multi-organizational
  contexts
- Fetching the user details from the Microsoft Graph API as instructed by the
  Microsoft docs (instead of relying on the data available in the access and ID
  tokens, which should be considered as opaque details not necessarily matching
  the correct user details)
- Automatically creating Decidim authorizations for the authenticated users
  based on the data of their organizational accounts (may be useful e.g. for
  limiting certain functionalities only for these users or only for users
  matching certain organizational details, such as their groups)
- Entra logout functionality

This module is originally based on a similar module (MSAD) but the key
difference is that the authentication works through the OICD protocol instead of
SAML in the other implementation. This makes the configuration process simpler
and provides some other benefits, such as the ability to easily connect to the
Microsoft Graph API with the issued access tokens.

The gem has been developed by [Mainio Tech](https://www.mainiotech.fi/).

Entra ID is a Microsoft product and is not related to this gem in any way, nor
do they provide technical support for it. Please contact the gem maintainers in
case you find any issues with it.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "decidim-entraid", github: "mainio/decidim-module-entraid"
```

And then execute:

```bash
$ bundle
```

After installation, you can add the initializer running the following command:

```bash
$ bundle exec rails generate decidim:entraid:install
```

This will add the `entraid` configuration block within your `config/secrets.yml`
file as well as the initializer to enable to Entra ID authentication option.

The following configurations need to be defined within your environment
variables according to your own configuration options:

```
ENTRAID_CLIENT_ID=define_your_client_id
ENTRAID_TENANT_ID=define_your_tenant_id
ENTRAID_CERT_PATH=define_path_to_certificate_file
ENTRAID_PKEY_PATH=define_path_to_private_key_file
```

By default, the Entra ID authentication is enabled for the development
environment only. In case you want to enable it for other environments as well,
apply the OmniAuth configuration keys accordingly to other environments as well.

The example configuration will set the `account-circle-line` icon for the the
authentication button from the Decidim's own iconset. In case you want to have a
better and more formal styling for the sign in button, you will need to
customize the sign in / sign up views.

### Connecting with multiple tenants

Once you have confirmed that the integration works with one tenant, you can
define as many tenants as you would like to within
`config/initializers/entraid.rb`. You can repeat the
`Decidim::EntraID.configure` call in that file for each tenant and give them
individual names. Note that the default name for the initial tenant is
`entraid` and the following tenants need to have a different name.

In case you are integrating with multiple tenants, it might be a good idea to
name the tenants using the organization names, e.g. if you were to connect to
the user directory of "Acme, Inc.", you could name the tenant `acmeinc`.

Once configured, please note that for the other tenant the authentication
endpoint urls shown in this document need to be modified according to the
tenant's name. By default, the tenant name for a single tenant is `entraid` in
which case the authentication URLs look as follows:

`https://www.example.org/users/auth/entraid/***`

When you configure the tenant's name to something else than the default, these
URLs will change accordingly. For example, if you used `acmeinc` and `eduorg` as
your tenant names, they would be as follows:

- `https://www.example.org/users/auth/acmeinc/***`
- `https://www.example.org/users/auth/eduorg/***`

### Configuring Entra ID

To configure Entra ID, follow these steps:

1.  Create a new certificate that will be used as a "password" for the system to
    connect to the MS APIs.
    * For local testing, you can use the following command:
      `openssl req -x509 -newkey rsa:4096 -keyout entraid.key -out entraid.crt -days 1460 -nodes`
    * Move them to the `config/cert` folder:
      `mkdir -p config/cert && mv entraid.* config/cert`
    * Do not commit these files to the code repository, keep them only locally
      in the connecting system only.
2.  Go to the [Entra admin center](https://entra.microsoft.com)
3.  Go to **App registrations**
4.  Create a **New registration**
5.  Provide the details for the login app, for example
    * App name: Decidim
    * Accounts in this organizational directory only
    * Platform: Web
    * Redirect URI: `https://www.example.org/users/auth/entraid/callback`
6.  Open the newly created app
7.  Copy the following details from the overview page to the environment
    variables:
    * `ENTRAID_CLIENT_ID=copy_application_client_id_here`
    * `ENTRAID_TENANT_ID=copy_directory_tenant_id_here`
8.  Configure the path to the certificate and the key to the environment
    variables:
    * `ENTRAID_CERT_PATH=config/cert/entraid.crt`
    * `ENTRAID_PKEY_PATH=config/cert/entraid.key`
9.  Go to the **Token configuration** section and add a new optional claim there
    as follows:
    * Click the **Add optional claim** button at the top of the view.
    * Select **Token type** as **ID**.
    * Select `login_hint` from the list that opens.
    * Click the **Add** button.
    * This will make the logout requests initiated from Decidim easier as the
      user does not have to manually select the account they want to logout
      from.
10. Go to the **API permissions** section and perform the following steps:
    * Make sure you have the `User.Read` permission enabled (should be enabled by
      default).
    * Click the "Grant admin consent for Organization" button in order to grant
      the application organizational consent for the given permissions
      (`User.Read`). Otherwise every login attempt requires user specific consent
      in order to utilize the user's information within the authenticating
      application (Decidim).
11. Go to the "Certificates & secrets" page of the application.
12. Upload the certificate and give it a description.

Optionally, you can also configure the front-channel logout URL for the app from
the **Authentication** -> **Settings** section. The logout URL is the following:

`https://www.example.org/users/auth/entraid/fclogout`

This step logs the user out of Decidim in case they log out from entra during
the same session.

## Usage

After the installation and configuration steps, you will need to enable the
Entra ID sign in method and authorization from Decidim's system management
panel. After enabled, you can start using it.

The Entra ID sign in method shipped with this gem will automatically authorize
the user accounts that signed in through Entra ID. In case the users already
have an account, they can still authorize their existing accounts using the
Entra ID authorization if they want to avoid generating multiple user accounts.
This happens from the authorizations section of the user profile pages.

The authentication process will perform the following steps:

- Finding a corresponding user identity, and if one does not exist, creates a
  new one.
- Finds the corresponding user to that identity, and if one does not exist,
  creates a new user account with the user details passed over from Entra ID.
- Finds the corresponding user authorization, and if one does not exist, creates
  a new user authorization with the user details passed over from Entra ID. If
  one exists, will update the details of that authorization with the details
  passed over from Entra ID. The attributes stored with this authorization can
  be customized through the metadata collector (e.g. user's groups).
- Initiates a new user session for the authenticated user.

## Customization

For some specific needs, you may need to store extra metadata for the Entra ID
authorization or add new authorization configuration options for the
authorization.

This can be achieved by applying the following configuration to the module
inside the initializer described above:

```ruby
# config/initializers/entraid.rb

Decidim::EntraID.configure do |config|
  # ... keep the default configuration as is ...
  # Add this extra configuration:
  config.workflow_configurator = lambda do |workflow|
    # When expiration is set to 0 minutes, it will never expire.
    workflow.expires_in = 0.minutes
    workflow.action_authorizer = "CustomEntraIDActionAuthorizer"
    workflow.options do |options|
      options.attribute :custom_option, type: :string, required: false
    end
  end
  config.metadata_collector_class = CustomEntraIDMetadataCollector
end
```

For the workflow configuration options, please refer to the
[decidim-verifications documentation](https://github.com/decidim/decidim/tree/develop/decidim-verifications).

For the custom metadata collector, please extend the default class as follows:

```ruby
# frozen_string_literal: true

class CustomEntraIDMetadataCollector < Decidim::EntraID::Verification::MetadataCollector
  def metadata
    super.tap do |data|
      # TBD
    end
  end
end
```

Please note that if you do not need to do very customized metadata collection,
customizing the metadata collector should not be necessary. Instead, you can use
the `metadata_attributes` configuration option which allows you to define the
attribute keys and their associated metadata keys to be stored with the user's
authorization. Customization of the metadata collector is only necessary in
cases where you need to calculate new values or process the original values
somehow prior to saving them to the user's metadata.

## Contributing

See [Decidim](https://github.com/decidim/decidim).

### Testing

To run the tests run the following in the gem development path:

```bash
$ bundle
$ DATABASE_USERNAME=<username> DATABASE_PASSWORD=<password> bundle exec rake test_app
$ DATABASE_USERNAME=<username> DATABASE_PASSWORD=<password> bundle exec rspec
```

Note that the database user has to have rights to create and drop a database in
order to create the dummy test app database.

In case you are using [rbenv](https://github.com/rbenv/rbenv) and have the
[rbenv-vars](https://github.com/rbenv/rbenv-vars) plugin installed for it, you
can add these environment variables to the root directory of the project in a
file named `.rbenv-vars`. In this case, you can omit defining these in the
commands shown above.

### Test code coverage

If you want to generate the code coverage report for the tests, you can use
the `SIMPLECOV=1` environment variable in the rspec command as follows:

```bash
$ SIMPLECOV=1 bundle exec rspec
```

This will generate a folder named `coverage` in the project root which contains
the code coverage report.

### Localization

Currently localization of the module happens in this repository only.

## License

See [LICENSE-AGPLv3.txt](LICENSE-AGPLv3.txt).
