from Resources.Vote import VotesResource, VoteCastResource


def register_vote_routes(api):
    """Register all vote related routes."""
    api.add_resource(VotesResource, "/api/v1/chamas/<int:chama_id>/votes")
    api.add_resource(VoteCastResource, "/api/v1/votes/<int:vote_id>/cast")