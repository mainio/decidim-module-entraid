# frozen_string_literal: true

module Decidim
  module EntraID
    module Test
      class OIDCServer
        attr_reader :tenant_id

        def initialize(tenant_id:)
          @tenant_id = tenant_id
          @identities = {}
          @string_generator = StringGenerator.new
        end

        # The authorization code is an opaque string but this tries to replicate
        # the format that is returned by MS (undocumented), just in case.
        def generate_authorization_code
          [
            "1",
            string_generator.base64_generate_random_string(39, [*0..255]),
            string_generator.base64_generate_random_string(635, [*0..255])
          ].join(".")
        end

        # Generates access token and ID token and returns the response hash that
        # would be normally returned by the token endpoint.
        def generate_token_response(identity:, client_id:, id_token_nonce:, app_name: "App name at MS")
          scope = "User.Read profile openid email"
          generator = PayloadGenerator.new(tenant_id:, client_id:, app_name:, identity:, scp: scope)

          access_token_payload = generator.access_token_payload
          access_token = JWT.encode(
            access_token_payload,
            private_key,
            "RS256",
            {
              typ: "JWT",
              nonce: generator.random_nonce,
              x5t: signing_jwk.kid,
              kid: signing_jwk.kid
            }
          )

          identities[access_token] = identity

          id_token_payload = generator.id_token_payload(nonce: id_token_nonce)
          id_token = JWT.encode(
            id_token_payload,
            private_key,
            "RS256",
            {
              typ: "JWT",
              kid: signing_jwk.kid
            }
          )

          expires_in = access_token_payload[:exp] - access_token_payload[:iat]

          # Note that the token response format is actually slightly different
          # than shown in the MS documentation. There is no refresh_token
          # included as these are supposed to live for a relatively short time
          # during the authentication flow.
          {
            token_type: "Bearer",
            scope:,
            expires_in:,
            ext_expires_in: expires_in,
            access_token:,
            id_token:
          }
        end

        # Generates the JWKs endpoint response hash.
        def generate_jwks_response
          jwks.export
        end

        # Validates the access token against the signature key.
        def access_token_valid?(access_token)
          JWT.decode(access_token, nil, true, { algorithms: %w(RS256).freeze, jwks: }).first

          true
        rescue JWT::DecodeError
          false
        end

        # Fetches an issued identity for a given access token.
        def identity_for(access_token)
          identities[access_token]
        end

        private

        attr_reader :identities, :string_generator

        def jwks
          @jwks ||= JWT::JWK::Set.new(
            JWT::JWK.new(private_key, use: "sig")
          )
        end

        def private_key
          @private_key ||= OpenSSL::PKey::RSA.new(2048)
        end

        def signing_jwk
          @signing_jwk ||= JWT::JWK.new(private_key)
        end

        # class Identity
        #   def given_name
        #     "John"
        #   end

        #   def family_name
        #     "Doe"
        #   end

        #   def name
        #     "#{given_name} #{family_name}"
        #   end

        #   def display_name
        #     name
        #   end

        #   def email
        #     "JohnDoe@contoso.onmicrosoft.com"
        #   end

        #   def principal_name
        #     email
        #   end

        #   def preferred_username
        #     email
        #   end

        #   def unique_name
        #     email
        #   end
        # end

        class PayloadGenerator
          def initialize(tenant_id:, client_id:, app_name:, identity:, scp:)
            @tenant_id = tenant_id
            @client_id = client_id
            @app_name = app_name
            @scp = scp
            @identity = identity
            @sid = SecureRandom.uuid
            @sub = SecureRandom.uuid
            @uti = generate_random_string(22, [45, *48..57, *65..90, *97..122])
            @iat = Time.current.to_i
          end

          # https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
          def access_token_payload
            {
              aud: client_id,
              iss: "https://sts.windows.net/#{tenant_id}/",
              iat:,
              exp: iat + 5166,
              acct: "0",
              acr: "1",
              aio: base64_generate_random_string(121, [*0..255]),
              amr: ["pwd"],
              app_displayname: app_name,
              appid: client_id,
              appidacr: "2",
              family_name: identity.family_name,
              given_name: identity.given_name,
              idtyp: "user",
              ipaddr: "1.2.3.4",
              name: identity.name,
              oid: identity.oid,
              platf: "8",
              puid: generate_random_string(16, [*48..57, *65..70]), # Passport UID (undocumented)
              rh: ["1", generate_random_string(54, [*48..57, *65..90, *97..122]), ""].join("."),
              scp:,
              sid:,
              sub:,
              tenant_region_scope: "EU",
              tid: tenant_id,
              unique_name: identity.unique_name,
              upn: identity.unique_name,
              uti:,
              ver: "1.0",
              wids: 2.times.map { SecureRandom.uuid },
              xms_acd: Time.current.to_i - 604_800,
              xms_act_fct: "9 3",
              xms_ftd: generate_random_string(60, [45, *48..57, *65..90, 95, *97..122]),
              xms_idrel: "1 20",
              xms_st: { sub: generate_random_string(43, [45, *48..57, *65..90, 95, *97..122]) },
              xms_sub_fct: "6 3",
              xms_tcdt: Time.current.to_i - 31_536_000,
              xms_tdbr: "EU",
              xms_tnt_fct: "3 12"
            }
          end

          def id_token_payload(nonce:)
            {
              aud: client_id,
              iss: "https://login.microsoftonline.com/#{tenant_id}/v2.0",
              iat:,
              nbf: iat,
              email: identity.email,
              login_hint:,
              name: identity.name,
              nonce:,
              oid: identity.oid,
              preferred_username: identity.preferred_username,
              rh: ["1", generate_random_string(54, [*48..57, *65..90, *97..122]), ""].join("."),
              sid:,
              sub:,
              tid: tenant_id,
              uti:,
              ver: "2.0"
            }
          end

          def random_nonce
            generate_random_string(43, [45, *48..57, *65..90, *97..122])
          end

          private

          attr_reader :tenant_id, :client_id, :app_name, :identity, :scp, :sid, :sub, :uti, :iat

          delegate :base64_generate_random_string, :generate_random_string, to: :string_generator

          def string_generator
            @string_generator ||= StringGenerator.new
          end

          # The login hint string is an opaque string and the format does not
          # really matter but this tries to emulate the format returned by the
          # endpoint, "just in case". Note that in real life this also has to be
          # specifically configured for it to be included in the ID token.
          def login_hint
            [
              "O",
              Base64.urlsafe_encode64(
                ["\n$", identity.oid, "\x12$", tenant_id, "\x1A)", "#{identity.unique_name} \t"].join
              )
            ].join(".")
          end
        end

        class StringGenerator
          def base64_generate_random_string(length, charcodes)
            Base64.urlsafe_encode64(generate_random_string(length, charcodes))
          end

          def generate_random_string(length, charcodes)
            length.times.map { charcodes.sample.chr }.join
          end
        end
      end
    end
  end
end
