# frozen_string_literal: true

require "spec_helper"

module Decidim::EntraID::Verification
  # Tests that the controller does not raise any exceptions when rendered.
  describe AuthorizationsController do
    routes { Decidim::EntraID::Verification::Engine.routes }

    render_views

    let(:user) { create(:user, :confirmed) }

    before do
      request.env["decidim.current_organization"] = user.organization
      sign_in user, scope: :user
    end

    describe "GET new" do
      it "redirects the user" do
        get :new
        expect(response).to render_template(:new)
        expect(response.body).to include("Redirection")
        expect(response.body).to include(%(href="/users/auth/entraid"))
      end
    end
  end
end
