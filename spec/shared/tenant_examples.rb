# frozen_string_literal: true

shared_examples "an EntraID tenant" do |name|
  subject do
    described_class.new do |config|
      config.name = name
    end
  end

  let(:certgen) { OmniAuth::EntraID::Test::CertificateGenerator.new }

  describe "#setup!" do
    let(:client_id) { double }
    let(:tenant_id) { double }
    let(:certificate) { certgen.certificate_for(private_key) }
    let(:private_key) { certgen.private_key }
    let(:extra_user_properties) { double }

    it "configures the routes" do
      subject.certificate = certificate
      subject.private_key = private_key

      expect(Decidim::EntraID::Engine).to receive(:routes)
      subject.setup!
    end

    it "configures the EntraID omniauth strategy for Devise" do
      subject.client_id = client_id
      subject.tenant_id = tenant_id
      subject.certificate = certificate
      subject.private_key = private_key
      subject.extra_user_properties = extra_user_properties

      expect(Devise).to receive(:setup) do |&block|
        config = double
        expect(config).to receive(:omniauth).with(
          name.to_sym,
          {
            name:,
            strategy_class: OmniAuth::Strategies::EntraID,
            client_id:,
            tenant_id:,
            certificate:,
            private_key:,
            extra_user_properties:
          }
        )
        block.call(config)
      end

      subject.setup!
    end
  end

  describe "#setup_routes!" do
    it "adds the correct callback and passthru routes to the core engine" do
      subject.setup_routes!

      %w(GET POST).each do |method|
        expect(
          Decidim::Core::Engine.routes.recognize_path("/users/auth/#{name}", method:)
        ).to eq(
          controller: "decidim/entraid/omniauth_callbacks",
          action: "passthru"
        )
      end

      expect(
        Decidim::Core::Engine.routes.recognize_path("/users/auth/#{name}/callback", method: "GET")
      ).to eq(
        controller: "decidim/entraid/omniauth_callbacks",
        action: "entraid"
      )
    end

    it "adds the correct sign out routes to the core engine" do
      %w(GET POST).each do |method|
        expect(
          Decidim::Core::Engine.routes.recognize_path("/users/auth/entraid/logout", method:)
        ).to eq(
          controller: "decidim/entraid/sessions",
          action: "logout"
        )
      end
    end
  end

  context "with mocked configuration" do
    describe "#certificate" do
      let(:certificate) { certgen.certificate_for(private_key) }
      let(:private_key) { certgen.private_key }

      it "returns a certificate instance when configured with a file" do
        file = double
        subject.certificate_file = file
        allow(File).to receive(:read).with(file).and_return(certificate.to_pem)

        expect(subject.certificate).to be_a(OpenSSL::X509::Certificate)
        expect(subject.certificate.to_pem).to eq(certificate.to_pem)
      end

      context "when configured through module configuration" do
        it "returns what is set by the module configuration" do
          subject.config.certificate = certificate
          expect(subject.certificate).to eq(certificate)
        end
      end
    end

    describe "#private_key" do
      let(:private_key) { certgen.private_key }

      it "returns a private key instance when configured with a file" do
        file = double
        subject.private_key_file = file
        allow(File).to receive(:read).with(file).and_return(private_key.to_pem)

        expect(subject.private_key).to be_a(OpenSSL::PKey::RSA)
        expect(subject.private_key.to_pem).to eq(private_key.to_pem)
      end

      context "when configured through module configuration" do
        it "returns what is set by the module configuration" do
          subject.config.private_key = private_key
          expect(subject.private_key).to eq(private_key)
        end
      end
    end

    describe "#omniauth_settings" do
      let(:client_id) { double }
      let(:tenant_id) { double }
      let(:certificate) { certgen.certificate_for(private_key) }
      let(:private_key) { certgen.private_key }
      let(:extra_user_properties) { double }

      it "returns the expected omniauth configuration hash" do
        subject.config.client_id = client_id
        subject.config.tenant_id = tenant_id
        subject.config.certificate = certificate
        subject.config.private_key = private_key
        subject.config.extra_user_properties = extra_user_properties

        expect(subject.omniauth_settings).to include(
          name:,
          strategy_class: OmniAuth::Strategies::EntraID,
          client_id:,
          tenant_id:,
          certificate:,
          private_key:,
          extra_user_properties:
        )
      end
    end

    describe "#application_host" do
      let(:rails_config) { double }
      let(:controller_config) { double }
      let(:mailer_config) { double }

      let(:controller_defaults) { nil }
      let(:mailer_defaults) { nil }

      before do
        allow(Rails.application).to receive(:config).and_return(rails_config)
        allow(rails_config).to receive(:action_controller).and_return(controller_config)
        allow(rails_config).to receive(:action_mailer).and_return(mailer_config)
        allow(controller_config).to receive(:default_url_options).and_return(controller_defaults)
        allow(mailer_config).to receive(:default_url_options).and_return(mailer_defaults)
      end

      it "returns the development host by default" do
        expect(subject.application_host).to eq("https://localhost:3000")
      end

      context "with controller config without a host" do
        let(:controller_defaults) { { port: 8000 } }

        it "returns the default development host without applying the configured port" do
          expect(subject.application_host).to eq("https://localhost:3000")
        end

        context "and mailer configuration having a host" do
          let(:mailer_defaults) { { host: "www.example.org" } }

          it "returns the mailer config host" do
            expect(subject.application_host).to eq("https://www.example.org")
          end
        end

        context "and mailer configuration having a host and a port" do
          let(:mailer_defaults) { { host: "www.example.org", port: 4443 } }

          it "returns the mailer config host and port" do
            expect(subject.application_host).to eq("https://www.example.org:4443")
          end
        end
      end

      context "with controller config having a host" do
        let(:controller_defaults) { { host: "www.example.org" } }
        let(:mailer_defaults) { { host: "www.mailer.org", port: 4443 } }

        it "returns the controller config host" do
          expect(subject.application_host).to eq("https://www.example.org")
        end
      end

      context "with controller config having a host and a port" do
        let(:controller_defaults) { { host: "www.example.org", port: 8080 } }
        let(:mailer_defaults) { { host: "www.mailer.org", port: 4443 } }

        it "returns the controller config host and port" do
          expect(subject.application_host).to eq("https://www.example.org:8080")
        end

        context "when the port is 80" do
          let(:controller_defaults) { { host: "www.example.org", port: 80 } }

          it "does not append it to the host" do
            expect(subject.application_host).to eq("http://www.example.org")
          end
        end

        context "when the port is 443" do
          let(:controller_defaults) { { host: "www.example.org", port: 443 } }

          it "does not append it to the host" do
            expect(subject.application_host).to eq("https://www.example.org")
          end
        end
      end

      context "with mailer config having a host" do
        let(:mailer_defaults) { { host: "www.example.org" } }

        it "returns the mailer config host" do
          expect(subject.application_host).to eq("https://www.example.org")
        end
      end

      context "with mailer config having a host and a port" do
        let(:mailer_defaults) { { host: "www.example.org", port: 8080 } }

        it "returns the mailer config host and port" do
          expect(subject.application_host).to eq("https://www.example.org:8080")
        end

        context "when the port is 80" do
          let(:mailer_defaults) { { host: "www.example.org", port: 80 } }

          it "does not append it to the host" do
            expect(subject.application_host).to eq("http://www.example.org")
          end
        end

        context "when the port is 443" do
          let(:mailer_defaults) { { host: "www.example.org", port: 443 } }

          it "does not append it to the host" do
            expect(subject.application_host).to eq("https://www.example.org")
          end
        end
      end
    end
  end
end
