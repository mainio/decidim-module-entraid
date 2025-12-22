# frozen_string_literal: true

FactoryBot.define do
  factory :entraid_identity, class: "Decidim::EntraID::Test::Identity" do
    transient do
      domain { "contoso.onmicrosoft.com" }
    end

    given_name { Faker::Name.first_name }
    family_name { Faker::Name.last_name }
    email do
      local_part = I18n.transliterate("#{given_name} #{family_name}").gsub(" ", ".")
      "#{local_part.downcase}@#{domain.downcase}"
    end
    principal_name { nil }
    preferred_username { nil }
    unique_name { nil }

    initialize_with do
      new(given_name:, family_name:, email:, principal_name:, preferred_username:, unique_name:)
    end
    skip_create
  end
end
