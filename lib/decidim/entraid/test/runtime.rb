# frozen_string_literal: true

require "webmock"

module Decidim
  module EntraID
    module Test
      class Runtime
        # Ability to stub the requests already in the control class
        include WebMock::API

        def self.initializer(&block)
          @block = block
        end

        def self.initialize
          new.instance_initialize(&@block)
        end

        def instance_initialize
          yield self if block_given?
        end
      end
    end
  end
end
