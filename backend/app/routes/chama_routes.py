from Resources.Chama import (
    ChamasResource,
    ChamaDetailResource,
    MembershipResource,
)


def register_chama_routes(api):
    """Register all chama related routes."""
    api.add_resource(ChamasResource, "/api/v1/chamas")
    api.add_resource(ChamaDetailResource, "/api/v1/chamas/<int:chama_id>")
    api.add_resource(MembershipResource, "/api/v1/chamas/<int:chama_id>/members")