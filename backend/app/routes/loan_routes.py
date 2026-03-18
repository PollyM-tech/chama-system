from flask import Blueprint
from flask_restful import Api
from Resources.Loan import (
    ChamaLoansResource,
    MyLoansResource,
    LoanDetailResource,
    LoanApprovalResource,
    LoanRejectionResource,
    LoanDisbursementResource,
    LoanRepaymentsResource,
)

loan_bp = Blueprint("loan_bp", __name__, url_prefix="/api")
api = Api(loan_bp)

api.add_resource(ChamaLoansResource, "/chamas/<int:chama_id>/loans")
api.add_resource(MyLoansResource, "/chamas/<int:chama_id>/my-loans")
api.add_resource(LoanDetailResource, "/chamas/<int:chama_id>/loans/<int:loan_id>")
api.add_resource(LoanApprovalResource, "/chamas/<int:chama_id>/loans/<int:loan_id>/approve")
api.add_resource(LoanRejectionResource, "/chamas/<int:chama_id>/loans/<int:loan_id>/reject")
api.add_resource(LoanDisbursementResource, "/chamas/<int:chama_id>/loans/<int:loan_id>/disburse")
api.add_resource(LoanRepaymentsResource, "/chamas/<int:chama_id>/loans/<int:loan_id>/repayments")


def register_loan_routes(app):
    app.register_blueprint(loan_bp)
