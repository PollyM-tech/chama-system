from flask import Blueprint
from flask_restful import Api
from Resources.User import (
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

user_bp = Blueprint("user_bp", __name__)
api = Api(user_bp)

api.add_resource(CurrentUserResource, "/me")
api.add_resource(UserProfileUpdateResource, "/me/update")
api.add_resource(ChangePasswordResource, "/me/change-password")
api.add_resource(MyChamasResource, "/my-chamas")

api.add_resource(UserListResource, "/users")
api.add_resource(UserDetailResource, "/users/<int:user_id>")
api.add_resource(UserMembershipsResource, "/users/<int:user_id>/memberships")
api.add_resource(SoftDeleteUserResource, "/users/<int:user_id>/soft-delete")
api.add_resource(RestoreUserResource, "/users/<int:user_id>/restore")
api.add_resource(DeactivateUserResource, "/users/<int:user_id>/deactivate")