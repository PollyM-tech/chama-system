from Resources.Contribution import (
    ContributionsResource,
    ChamaContributionsResource,
    ContributionSummaryResource,
)


def register_contribution_routes(api):
    """Register all contribution related routes."""
    api.add_resource(ContributionsResource, "/api/v1/contributions")
    api.add_resource(
        ChamaContributionsResource,
        "/api/v1/chamas/<int:chama_id>/contributions"
    )
    api.add_resource(
        ContributionSummaryResource,
        "/api/v1/chamas/<int:chama_id>/contributions/summary"
    )