from Resources.Loan import (
    LoansResource,
    LoanCalculatorResource,
    LoanManagementResource,
)


def register_loan_routes(api):
    """Register all loan related routes."""
    api.add_resource(LoansResource, "/api/v1/loans")
    api.add_resource(LoanCalculatorResource, "/api/v1/loans/calculator")

    api.add_resource(
        LoanManagementResource,
        "/api/v1/chamas/<int:chama_id>/loans"
    )

    api.add_resource(
        LoanManagementResource,
        "/api/v1/chamas/<int:chama_id>/loans/<int:loan_id>",
        endpoint="loan_management"
    )