from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Loan, Membership, Chama
from schemas import loan_schema, loans_schema, loan_calculator_schema
from marshmallow import ValidationError
from datetime import datetime, timedelta

class LoansResource(Resource):
    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        
        try:
            data = loan_schema.load(request.get_json())
        except ValidationError as err:
            return {"errors": err.messages}, 400

        # Check if user is active member of the chama
        membership = Membership.query.filter_by(
            user_id=user_id, 
            chama_id=data.chama_id,
            status='active'
        ).first()
        
        if not membership:
            return {"message": "Not an active member of this chama"}, 403

        # Check for existing pending loans
        existing_loan = Loan.query.filter_by(
            user_id=user_id,
            chama_id=data.chama_id,
            status='requested'
        ).first()
        
        if existing_loan:
            return {"message": "You already have a pending loan request"}, 422

        # Calculate due date (default 6 months from now)
        due_date = datetime.utcnow() + timedelta(days=180)

        loan = Loan(
            chama_id=data.chama_id,
            user_id=user_id,
            amount=data.amount,
            interest_rate=data.interest_rate or 10.0,  # Default interest
            due_date=due_date,
            status='requested'
        )

        db.session.add(loan)
        db.session.commit()

        return {
            "message": "Loan application submitted successfully",
            "loan": loan_schema.dump(loan)
        }, 201

    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        
        chama_id = request.args.get('chama_id')
        status = request.args.get('status')
        
        query = Loan.query.filter_by(user_id=user_id)
        
        if chama_id:
            query = query.filter_by(chama_id=chama_id)
        if status:
            query = query.filter_by(status=status)
            
        loans = query.all()
        return loans_schema.dump(loans), 200

class LoanCalculatorResource(Resource):
    def post(self):
        try:
            data = loan_calculator_schema.load(request.get_json())
        except ValidationError as err:
            return {"errors": err.messages}, 400

        amount = data['amount']
        interest_rate = data['interest_rate']
        term_months = data['term_months']

        # Calculate loan details
        monthly_interest_rate = interest_rate / 100 / 12
        total_interest = amount * monthly_interest_rate * term_months
        total_repayment = amount + total_interest
        monthly_repayment = total_repayment / term_months

        return {
            "loan_amount": amount,
            "interest_rate": interest_rate,
            "term_months": term_months,
            "total_interest": round(total_interest, 2),
            "total_repayment": round(total_repayment, 2),
            "monthly_repayment": round(monthly_repayment, 2)
        }, 200

class LoanManagementResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user_id = get_jwt_identity()
        
        # Check if user is admin of the chama
        admin_membership = Membership.query.filter_by(
            user_id=current_user_id,
            chama_id=chama_id,
            role__in=['chairperson', 'treasurer']
        ).first()
        
        if not admin_membership:
            return {"message": "Only admins can view all loans"}, 403

        status = request.args.get('status')
        query = Loan.query.filter_by(chama_id=chama_id)
        
        if status:
            query = query.filter_by(status=status)
            
        loans = query.all()
        
        loans_data = []
        for loan in loans:
            loan_data = loan_schema.dump(loan)
            loan_data['user_name'] = loan.user.username
            loan_data['user_email'] = loan.user.email
            loans_data.append(loan_data)

        return loans_data, 200

    @jwt_required()
    def put(self, chama_id, loan_id):
        current_user_id = get_jwt_identity()
        
        # Check if user is admin of the chama
        admin_membership = Membership.query.filter_by(
            user_id=current_user_id,
            chama_id=chama_id,
            role__in=['chairperson', 'treasurer']
        ).first()
        
        if not admin_membership:
            return {"message": "Only admins can manage loans"}, 403

        loan = Loan.query.filter_by(id=loan_id, chama_id=chama_id).first()
        if not loan:
            return {"message": "Loan not found"}, 404

        try:
            data = request.get_json()
            new_status = data.get('status')
            if new_status not in ['approved', 'rejected', 'active', 'completed']:
                return {"message": "Invalid status"}, 400

            loan.status = new_status
            if new_status == 'approved':
                loan.approved_at = datetime.utcnow()

            db.session.commit()

            return {
                "message": f"Loan {new_status} successfully",
                "loan": loan_schema.dump(loan)
            }, 200

        except Exception as e:
            return {"message": str(e)}, 500