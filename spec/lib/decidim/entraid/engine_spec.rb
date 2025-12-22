# frozen_string_literal: true

require "spec_helper"

module Decidim
  module EntraID
    describe Engine do
      # Some of the tests may be causing the Devise OmniAuth strategies to be
      # reconfigured in which case the strategy option information is lost in
      # the Devise configurations. In case the strategy is lost, re-initialize
      # it manually. Normally this is done when the application's middleware
      # stack is loaded.
      after do
        Decidim::EntraID.tenants do |tenant|
          name = tenant.name.to_sym
          next if ::Devise.omniauth_configs[name].strategy

          ::OmniAuth::Strategies::EntraID.new(
            Rails.application,
            tenant.omniauth_settings
          ) do |strategy|
            ::Devise.omniauth_configs[name].strategy = strategy
          end
        end
      end

      it "mounts the routes to the core engine" do
        routes = double
        allow(Decidim::Core::Engine).to receive(:routes).and_return(routes)
        expect(Decidim::Core::Engine).to receive(:routes)
        expect(routes).to receive(:prepend) do |&block|
          context = double
          expect(context).to receive(:mount).with(described_class => "/")
          context.instance_eval(&block)
        end

        run_initializer("decidim_entraid.mount_routes")
      end

      it "adds the correct sign out routes to the core engine" do
        %w(DELETE POST).each do |method|
          expect(
            Decidim::Core::Engine.routes.recognize_path("/users/sign_out", method:)
          ).to eq(
            controller: "decidim/entraid/sessions",
            action: "destroy"
          )
        end
      end

      it "configures the EntraID omniauth strategy for Devise" do
        expect(::Devise).to receive(:setup) do |&block|
          config = double
          expect(config).to receive(:omniauth).with(
            :entraid,
            {
              name: "entraid",
              strategy_class: OmniAuth::Strategies::EntraID,
              client_id: "00001111-aaaa-2222-bbbb-3333cccc4444",
              tenant_id: "aaaabbbb-0000-cccc-1111-dddd2222eeee",
              certificate: an_instance_of(OpenSSL::X509::Certificate),
              private_key: an_instance_of(OpenSSL::PKey::RSA),
              extra_user_properties: nil
            }
          )
          block.call(config)
        end
        expect(::Devise).to receive(:setup) do |&block|
          config = double
          expect(config).to receive(:omniauth).with(
            :other,
            {
              name: "other",
              strategy_class: OmniAuth::Strategies::EntraID,
              client_id: "11112222-bbbb-3333-cccc-4444dddd5555",
              tenant_id: "bbbbcccc-1111-dddd-2222-eeee3333ffff",
              certificate: an_instance_of(OpenSSL::X509::Certificate),
              private_key: an_instance_of(OpenSSL::PKey::RSA),
              extra_user_properties: nil
            }
          )
          block.call(config)
        end

        allow(Decidim::EntraID).to receive(:initialized?).and_return(false)
        run_initializer("decidim_entraid.setup")
      end

      it "configures the OmniAuth failure app" do
        expect(OmniAuth.config).to receive(:on_failure=) do |proc|
          env = double
          action = double
          expect(env).to receive(:[]).with("PATH_INFO").twice.and_return(
            "/users/auth/entraid"
          )
          expect(env).to receive(:[]=).with("devise.mapping", ::Devise.mappings[:user])
          allow(Decidim::EntraID::OmniauthCallbacksController).to receive(
            :action
          ).with(:failure).and_return(action)
          expect(Decidim::EntraID::OmniauthCallbacksController).to receive(:action)
          expect(action).to receive(:call).with(env)

          proc.call(env)
        end
        expect(OmniAuth.config).to receive(:on_failure=) do |proc|
          env = double
          action = double
          expect(env).to receive(:[]).with("PATH_INFO").twice.and_return(
            "/users/auth/other"
          )
          expect(env).to receive(:[]=).with("devise.mapping", ::Devise.mappings[:user])
          allow(Decidim::EntraID::OmniauthCallbacksController).to receive(
            :action
          ).with(:failure).and_return(action)
          expect(Decidim::EntraID::OmniauthCallbacksController).to receive(:action)
          expect(action).to receive(:call).with(env)

          proc.call(env)
        end

        allow(Decidim::EntraID).to receive(:initialized?).and_return(false)
        run_initializer("decidim_entraid.setup")
      end

      it "falls back on the default OmniAuth failure app" do
        failure_app = double

        expect(OmniAuth.config).to receive(:on_failure).twice.and_return(failure_app)
        expect(OmniAuth.config).to receive(:on_failure=).twice do |proc|
          env = double
          expect(env).to receive(:[]).with("PATH_INFO").twice.and_return(
            "/something/else"
          )
          expect(failure_app).to receive(:call).with(env)

          proc.call(env)
        end

        allow(Decidim::EntraID).to receive(:initialized?).and_return(false)
        run_initializer("decidim_entraid.setup")
      end

      it "adds the mail interceptor" do
        expect(ActionMailer::Base).to receive(:register_interceptor).with(
          Decidim::EntraID::MailInterceptors::GeneratedRecipientsInterceptor
        )

        run_initializer("decidim_entraid.mail_interceptors")
      end

      def run_initializer(initializer_name)
        config = described_class.initializers.find do |i|
          i.name == initializer_name
        end
        config.run
      end
    end
  end
end
