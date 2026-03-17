from flask import Blueprint
from flask_restful import Api
from Resources.Contribution import (
    ContributionCreateResource,
    ChamaContributionListResource,
    MyContributionHistoryResource,
    MemberContributionHistoryResource,
    ContributionUpdateResource,
    ContributionDeleteResource,
    ContributionSummaryResource,
)

contribution_bp = Blueprint("contribution_bp", __name__)
api = Api(contribution_bp)

api.add_resource(ContributionCreateResource, "/chamas/<int:chama_id>/contributions")
api.add_resource(ChamaContributionListResource, "/chamas/<int:chama_id>/contributions")
api.add_resource(MyContributionHistoryResource, "/chamas/<int:chama_id>/my-contributions")
api.add_resource(MemberContributionHistoryResource, "/chamas/<int:chama_id>/members/<int:user_id>/contributions")
api.add_resource(ContributionUpdateResource, "/chamas/<int:chama_id>/contributions/<int:contribution_id>")
api.add_resource(ContributionDeleteResource, "/chamas/<int:chama_id>/contributions/<int:contribution_id>")
api.add_resource(ContributionSummaryResource, "/chamas/<int:chama_id>/contributions/summary")