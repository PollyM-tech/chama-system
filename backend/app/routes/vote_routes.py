from flask import Blueprint
from flask_restful import Api
from Resources.Vote import (
    ChamaPollsResource,
    PollDetailResource,
    PollUpdateResource,
    PollDeleteResource,
    CastVoteResource,
    MyPollVoteResource,
    PollVotesResource,
)

vote_bp = Blueprint("vote_bp", __name__, url_prefix="/api")
api = Api(vote_bp)

api.add_resource(ChamaPollsResource, "/chamas/<int:chama_id>/polls")
api.add_resource(PollDetailResource, "/chamas/<int:chama_id>/polls/<int:poll_id>")
api.add_resource(PollUpdateResource, "/chamas/<int:chama_id>/polls/<int:poll_id>")
api.add_resource(PollDeleteResource, "/chamas/<int:chama_id>/polls/<int:poll_id>")
api.add_resource(CastVoteResource, "/chamas/<int:chama_id>/polls/<int:poll_id>/vote")
api.add_resource(MyPollVoteResource, "/chamas/<int:chama_id>/polls/<int:poll_id>/my-vote")
api.add_resource(PollVotesResource, "/chamas/<int:chama_id>/polls/<int:poll_id>/votes")


def register_vote_routes(app):
    app.register_blueprint(vote_bp)