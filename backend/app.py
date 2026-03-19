from flask import Flask
from flask_restful import Api
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os

from models import db

from Resources.User import (
    SignUpResource,
    LoginResource,
    RefreshTokenResource,
    CurrentUserResource,
    UserProfileUpdateResource,
    ChangePasswordResource,
    MyChamasResource,
    UserMembershipsResource,
    UserDetailResource,
    UserListResource,
    SoftDeleteUserResource,
    RestoreUserResource,
    DeactivateUserResource,
)

# Chama Resources
from Resources.Chama import (
    ChamaCreateResource,
    ChamaDetailResource,
    ChamaMembersResource,
    ChamaInviteMemberResource,
    ChamaPendingInvitesResource,
    ChamaRevokeInviteResource,
    ChamaAddExistingMemberResource,
    ChamaMembershipRoleUpdateResource,
    ChamaSuspendMembershipResource,
    ChamaRemoveMembershipResource,
)

load_dotenv()

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(BASE_DIR, 'chama.db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret-change-this")
app.config["PROPAGATE_EXCEPTIONS"] = True
app.config["FRONTEND_URL"] = os.getenv("FRONTEND_URL", "*")

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
api = Api(app)
CORS(app, resources={r"/api/*": {"origins": app.config["FRONTEND_URL"]}})

# User Routes
api.add_resource(SignUpResource, "/api/auth/signup")
api.add_resource(LoginResource, "/api/auth/login")
api.add_resource(RefreshTokenResource, "/api/auth/refresh")
#
api.add_resource(CurrentUserResource, "/api/me")
api.add_resource(UserProfileUpdateResource, "/api/me/update")
api.add_resource(ChangePasswordResource, "/api/me/change-password")
api.add_resource(MyChamasResource, "/api/my-chamas")

api.add_resource(UserListResource, "/api/users")
api.add_resource(UserDetailResource, "/api/users/<int:user_id>")
api.add_resource(UserMembershipsResource, "/api/users/<int:user_id>/memberships")
api.add_resource(SoftDeleteUserResource, "/api/users/<int:user_id>/soft-delete")
api.add_resource(RestoreUserResource, "/api/users/<int:user_id>/restore")
api.add_resource(DeactivateUserResource, "/api/users/<int:user_id>/deactivate")

# CHAMA ROUTES
api.add_resource(ChamaCreateResource, "/api/chamas")
api.add_resource(ChamaDetailResource, "/api/chamas/<int:chama_id>")
api.add_resource(ChamaMembersResource, "/api/chamas/<int:chama_id>/members")
api.add_resource(ChamaInviteMemberResource, "/api/chamas/<int:chama_id>/invite")
api.add_resource(ChamaPendingInvitesResource, "/api/chamas/<int:chama_id>/invites")
api.add_resource(ChamaRevokeInviteResource, "/api/chamas/<int:chama_id>/invites/<int:invite_id>/revoke")
api.add_resource(ChamaAddExistingMemberResource, "/api/chamas/<int:chama_id>/memberships")
api.add_resource(ChamaMembershipRoleUpdateResource, "/api/chamas/<int:chama_id>/memberships/<int:membership_id>/role")
api.add_resource(ChamaSuspendMembershipResource, "/api/chamas/<int:chama_id>/memberships/<int:membership_id>/suspend")
api.add_resource(ChamaRemoveMembershipResource, "/api/chamas/<int:chama_id>/memberships/<int:membership_id>/remove")

@app.route("/")
def home():
    return {"message": "Chama API is running successfully."}, 200


if __name__ == "__main__":
    app.run(debug=True)