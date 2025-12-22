# frozen_string_literal: true

require "omniauth"
require "omniauth/strategies/entraid"

require_relative "entraid/version"
require_relative "entraid/engine"
require_relative "entraid/authentication"
require_relative "entraid/verification"
require_relative "entraid/mail_interceptors"

module Decidim
  module EntraID
    autoload :Tenant, "decidim/entraid/tenant"

    class << self
      def tenants
        @tenants ||= []
      end

      def test!
        @test = true
      end

      def configure(&)
        tenant = Decidim::EntraID::Tenant.new(&)
        tenants.each do |existing|
          next unless tenant.name == existing.name

          raise(
            InvalidTenantName,
            "Please define an individual name for the Entra ID tenant. The name \"#{tenant.name}\" is already in use."
          )
        end

        tenants << tenant
      end

      def setup!
        raise "Entra ID module is already initialized!" if initialized?

        @initialized = true
        tenants.each(&:setup!)
      end

      private

      def initialized?
        @initialized
      end
    end

    class InvalidTenantName < StandardError; end
  end
end
