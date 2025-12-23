# frozen_string_literal: true

source "https://rubygems.org"

ruby RUBY_VERSION

# Inside the development app, the relative require has to be one level up, as
# the Gemfile is copied to the development_app folder (almost) as is.
base_path = ""
base_path = "../" if File.basename(__dir__) == "development_app"
require_relative "#{base_path}lib/decidim/entraid/version"

DECIDIM_VERSION = Decidim::EntraID::DECIDIM_VERSION

gem "decidim", DECIDIM_VERSION
gem "decidim-entraid", path: "."

gem "bootsnap", "~> 1.4"
gem "puma", ">= 6.3.1"

group :development, :test do
  gem "byebug", "~> 11.0", platform: :mri

  gem "decidim-dev", DECIDIM_VERSION

  # Pinned due to the following bug:
  # https://github.com/jessebs/simplecov-cobertura/issues/48
  #
  # Apparently fixed in later versions of simplecov-cobertura but Decidim
  # currently locks the version to ~> 2.1.0.
  gem "rexml", "3.4.1"
end

group :development do
  gem "faker", "~> 3.2"
  gem "letter_opener_web", "~> 2.0"
  gem "listen", "~> 3.1"
  gem "web-console", "~> 4.2"
end
