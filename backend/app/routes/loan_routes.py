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
    LoanUpdateResource,
    LoanDeleteResource,
)

loan_bp = Blueprint("loan_bp", __name__)
api = Api(loan_bp)

api.add_resource(ChamaLoansResource, "/chamas/<int:chama_id>/loans")
api.add_resource(MyLoansResource, "/chamas/<int:chama_id>/my-loans")
api.add_resource(LoanDetailResource, "/chamas/<int:chama_id>/loans/<int:loan_id>")
api.add_resource(LoanApprovalResource, "/chamas/<int:chama_id>/loans/<int:loan_id>/approve")
api.add_resource(LoanRejectionResource, "/chamas/<int:chama_id>/loans/<int:loan_id>/reject")
api.add_resource(LoanDisbursementResource, "/chamas/<int:chama_id>/loans/<int:loan_id>/disburse")
api.add_resource(LoanRepaymentsResource, "/chamas/<int:chama_id>/loans/<int:loan_id>/repayments")
api.add_resource(LoanUpdateResource, "/chamas/<int:chama_id>/loans/<int:loan_id>")
api.add_resource(LoanDeleteResource, "/chamas/<int:chama_id>/loans/<int:loan_id>")