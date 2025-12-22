# frozen_string_literal: true

lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "decidim/entraid/version"

Gem::Specification.new do |spec|
  spec.name = "decidim-entraid"
  spec.version = Decidim::EntraID::VERSION
  spec.authors = ["Antti Hukkanen"]
  spec.email = ["antti.hukkanen@mainiotech.fi"]
  spec.required_ruby_version = ">= 3.2"

  spec.summary = "Provides possibility to bind Microsoft Entra ID authentication provider to Decidim."
  spec.description = "Adds Microsoft Entra ID authentication provider to Decidim."
  spec.homepage = "https://github.com/mainio/decidim-module-entraid"
  spec.license = "AGPL-3.0"

  spec.files = Dir[
    "{app,config,lib}/**/*",
    "LICENSE-AGPLv3.txt",
    "Rakefile",
    "README.md"
  ]

  spec.require_paths = ["lib"]

  spec.add_dependency "decidim-core", Decidim::EntraID::DECIDIM_VERSION
  spec.add_dependency "omniauth-oauth2", "~> 1.8"

  spec.metadata["rubygems_mfa_required"] = "true"
end
