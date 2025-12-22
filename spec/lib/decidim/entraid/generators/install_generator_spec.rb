# frozen_string_literal: true

require "spec_helper"
require "rails/generators"
require "generators/decidim/entraid/install_generator"

module Decidim
  module EntraID
    module Generators
      describe InstallGenerator do
        let(:options) { {} }

        before { allow(subject).to receive(:options).and_return(options) }

        describe "#copy_initializer" do
          it "copies the initializer file" do
            expect(subject).to receive(:copy_file).with(
              "entraid_initializer.rb",
              "config/initializers/entraid.rb"
            )
            subject.copy_initializer
          end

          context "with the test_initializer option set to true" do
            let(:options) { { test_initializer: true } }

            it "copies the test initializer file" do
              expect(subject).to receive(:copy_file).with(
                "entraid_initializer_test.rb",
                "config/initializers/entraid.rb"
              )
              subject.copy_initializer
            end
          end
        end

        describe "#enable_authentication" do
          let(:secrets_yml_template) do
            yml = "default: &default\n"
            yml += "  omniauth:\n"
            yml += "    facebook:\n"
            yml += "      enabled: false\n"
            yml += "      app_id: 1234\n"
            yml += "      app_secret: 4567\n"
            yml += "%ENTRAID_INJECTION_DEFAULT%"
            yml += "  geocoder:\n"
            yml += "    here_app_id: 1234\n"
            yml += "    here_app_code: 1234\n"
            yml += "\n"
            yml += "development:\n"
            yml += "  <<: *default\n"
            yml += "  secret_key_base: aaabbb\n"
            yml += "  omniauth:\n"
            yml += "    developer:\n"
            yml += "      enabled: true\n"
            yml += "      icon: phone\n"
            yml += "%ENTRAID_INJECTION_DEVELOPMENT%"
            yml += "\n"
            yml += "test:\n"
            yml += "  <<: *default\n"
            yml += "  secret_key_base: cccddd\n"
            yml += "\n"

            yml
          end

          let(:secrets_yml) do
            secrets_yml_template.gsub(
              "%ENTRAID_INJECTION_DEFAULT%",
              ""
            ).gsub(
              "%ENTRAID_INJECTION_DEVELOPMENT%",
              ""
            )
          end

          let(:secrets_yml_modified) do
            default = "    entraid:\n"
            default += "      enabled: false\n"
            default += "      icon: account-circle-line\n"
            default += "      client_id: <%= ENV[\"ENTRAID_CLIENT_ID\"] %>\n"
            default += "      tenant_id: <%= ENV[\"ENTRAID_TENANT_ID\"] %>\n"
            default += "      certificate_file: <%= ENV[\"ENTRAID_CERT_PATH\"] %>\n"
            default += "      private_key_file: <%= ENV[\"ENTRAID_PKEY_PATH\"] %>\n"
            development = "    entraid:\n"
            development += "      enabled: true\n"
            development += "      icon: account-circle-line\n"
            development += "      client_id: <%= ENV[\"ENTRAID_CLIENT_ID\"] %>\n"
            development += "      tenant_id: <%= ENV[\"ENTRAID_TENANT_ID\"] %>\n"
            development += "      certificate_file: <%= ENV[\"ENTRAID_CERT_PATH\"] %>\n"
            development += "      private_key_file: <%= ENV[\"ENTRAID_PKEY_PATH\"] %>\n"

            secrets_yml_template.gsub(
              "%ENTRAID_INJECTION_DEFAULT%",
              default
            ).gsub(
              "%ENTRAID_INJECTION_DEVELOPMENT%",
              development
            )
          end

          it "enables the Entra ID authentication by modifying the secrets.yml file" do
            allow(File).to receive(:read).and_return(secrets_yml)
            expect(File).to receive(:read)
            allow(File).to receive(:readlines).and_return(secrets_yml.lines)
            expect(File).to receive(:readlines)
            expect(File).to receive(:open).with(anything, "w") do |&block|
              file = double
              expect(file).to receive(:puts).with(secrets_yml_modified)
              block.call(file)
            end
            expect(subject).to receive(:say_status).with(
              :insert,
              "config/secrets.yml",
              :green
            )

            subject.enable_authentication
          end

          context "with Entra ID already enabled" do
            it "reports identical status" do
              allow(YAML).to receive(:safe_load).and_return(
                "default" => { "omniauth" => { "entraid" => {} } }
              )
              expect(YAML).to receive(:safe_load)
              expect(subject).to receive(:say_status).with(
                :identical,
                "config/secrets.yml",
                :blue
              )

              subject.enable_authentication
            end
          end
        end
      end
    end
  end
end
