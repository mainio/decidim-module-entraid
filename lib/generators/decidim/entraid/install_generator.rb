# frozen_string_literal: true

require "rails/generators/base"

module Decidim
  module EntraID
    module Generators
      class InstallGenerator < Rails::Generators::Base
        source_root File.expand_path("../../templates", __dir__)

        desc "Creates a Devise initializer and copy locale files to your application."

        class_option(
          :dummy_cert,
          desc: "Defines whether to create a dummy certificate for localhost.",
          type: :boolean,
          default: false
        )

        class_option(
          :test_initializer,
          desc: "Copies the test initializer instead of the actual one (for test dummy app).",
          type: :boolean,
          default: false,
          hide: true
        )

        def self.namespace(name = nil)
          super.sub(":entra_i_d:", ":entraid:")
        end

        def copy_initializer
          if options[:test_initializer]
            copy_file "entraid_initializer_test.rb", "config/initializers/entraid.rb"
          else
            copy_file "entraid_initializer.rb", "config/initializers/entraid.rb"
          end
        end

        def enable_authentication
          secrets_path = Rails.application.root.join("config", "secrets.yml")
          evaluated_secrets = ERB.new(File.read(secrets_path))
          secrets = YAML.safe_load(evaluated_secrets.result, aliases: true)

          if secrets["default"]["omniauth"]["entraid"]
            say_status :identical, "config/secrets.yml", :blue
          else
            mod = SecretsModifier.new(secrets_path)
            final = mod.modify

            target_path = Rails.application.root.join("config", "secrets.yml")
            File.open(target_path, "w") { |f| f.puts final }

            say_status :insert, "config/secrets.yml", :green
          end
        end

        class SecretsModifier
          def initialize(filepath)
            @filepath = filepath
          end

          def modify
            self.inside_config = false
            self.inside_omniauth = false
            self.config_branch = nil
            @final = ""

            @empty_line_count = 0
            File.readlines(filepath).each do |line|
              if line.match?(/^$/)
                @empty_line_count += 1
                next
              else
                handle_line line
                insert_empty_lines
              end

              @final += line
            end
            insert_empty_lines

            @final
          end

          private

          attr_accessor :filepath, :empty_line_count, :inside_config, :inside_omniauth, :config_branch

          def handle_line(line)
            if inside_config && line.match?(/^  omniauth:/)
              self.inside_omniauth = true
            elsif inside_omniauth && (line.match?(/^(  )?[a-z]+/) || line.match?(/^#.*/))
              inject_entraid_config
              self.inside_omniauth = false
            end

            return unless line.match?(/^[a-z]+/)

            # A new root configuration block starts
            self.inside_config = false
            self.inside_omniauth = false

            branch = line[/^(default|development|test):/, 1]
            if branch
              self.inside_config = true
              self.config_branch = branch.to_sym
            end
          end

          def insert_empty_lines
            @final += "\n" * empty_line_count
            @empty_line_count = 0
          end

          def inject_entraid_config
            @final += "    entraid:\n"
            @final += case config_branch
                      when :development, :test
                        "      enabled: true\n"
                      else
                        "      enabled: false\n"
                      end
            @final += "      icon: account-circle-line\n"
            @final += "      client_id: <%= ENV[\"ENTRAID_CLIENT_ID\"] %>\n"
            @final += "      tenant_id: <%= ENV[\"ENTRAID_TENANT_ID\"] %>\n"
            @final += "      certificate_file: <%= ENV[\"ENTRAID_CERT_PATH\"] %>\n"
            @final += "      private_key_file: <%= ENV[\"ENTRAID_PKEY_PATH\"] %>\n"
          end
        end
      end
    end
  end
end
