from flask import Blueprint
from flask_restful import Api
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

chama_bp = Blueprint("chama_bp", __name__, url_prefix="/api")
api = Api(chama_bp)

api.add_resource(ChamaCreateResource, "/chamas")
api.add_resource(ChamaDetailResource, "/chamas/<int:chama_id>")
api.add_resource(ChamaMembersResource, "/chamas/<int:chama_id>/members")
api.add_resource(ChamaInviteMemberResource, "/chamas/<int:chama_id>/invite")
api.add_resource(ChamaPendingInvitesResource, "/chamas/<int:chama_id>/invites")
api.add_resource(ChamaRevokeInviteResource, "/chamas/<int:chama_id>/invites/<int:invite_id>/revoke")
api.add_resource(ChamaAddExistingMemberResource, "/chamas/<int:chama_id>/memberships")
api.add_resource(ChamaMembershipRoleUpdateResource, "/chamas/<int:chama_id>/memberships/<int:membership_id>/role")
api.add_resource(ChamaSuspendMembershipResource, "/chamas/<int:chama_id>/memberships/<int:membership_id>/suspend")
api.add_resource(ChamaRemoveMembershipResource, "/chamas/<int:chama_id>/memberships/<int:membership_id>/remove")


def register_chama_routes(app):
    app.register_blueprint(chama_bp)
