# frozen_string_literal: true

module Decidim
  module EntraID
    module Test
      Identity = Struct.new(
        :given_name,
        :family_name,
        :email,
        # Unnecessary attributes
        :principal_name,
        :preferred_username,
        :unique_name,
        keyword_init: true
      ) do
        def oid
          @oid ||= SecureRandom.uuid
        end

        def name
          "#{given_name} #{family_name}"
        end

        def display_name
          name
        end

        def principal_name
          self[:principal_name] || email
        end

        def preferred_username
          self[:preferred_username] || email
        end

        def unique_name
          self[:unique_name] || email
        end
      end
    end
  end
end
