# frozen_string_literal: true

module Decidim
  module EntraID
    module Test
      class MsgraphAPI
        def initialize(identity_server)
          @identity_server = identity_server
        end

        def serve(request)
          return serve_not_found unless request.method == :get
          return serve_not_found unless request.uri.path == "/v1.0/me"

          identity = authorize!(request)

          params = Rack::Utils.parse_query(request.uri.query)
          select = params["$select"] || "displayName,givenName,surname,mail,userPrincipalName"
          props = select.split(",")

          available_data = {
            "displayName" => identity.display_name,
            "givenName" => identity.given_name,
            "surname" => identity.family_name,
            "mail" => identity.email,
            "userPrincipalName" => identity.principal_name
          }
          selected_data = props.filter { |p| available_data.has_key?(p) }.index_with { |key| available_data[key] }

          graph_response = {
            "@odata.context" => "https://graph.microsoft.com/v1.0/$metadata#users(#{selected_data.keys.join(",")})/$entity"
          }.merge(selected_data)

          {
            status: 200,
            body: graph_response.to_json,
            headers: {
              "Content-Type" => "application/json"
            }
          }
        rescue UnauthorizedError
          {
            status: 401,
            body: { error: "Unauthorized." }.to_json,
            headers: {
              "Content-Type" => "application/json"
            }
          }
        end

        private

        attr_reader :identity_server

        def serve_not_found
          {
            status: 404,
            body: { error: "Not found." }.to_json,
            headers: {
              "Content-Type" => "application/json"
            }
          }
        end

        def authorize!(request)
          authorization = request.headers["Authorization"]
          raise UnauthorizedError unless authorization

          match = authorization.match(/^Bearer\s+(.*)/)
          raise UnauthorizedError unless match

          raise UnauthorizedError unless identity_server.access_token_valid?(match[1])

          identity = identity_server.identity_for(match[1])
          raise UnauthorizedError unless identity

          identity
        end

        class UnauthorizedError < StandardError; end
      end
    end
  end
end
