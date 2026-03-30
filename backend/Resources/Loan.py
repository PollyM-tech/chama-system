from datetime import datetime
from decimal import Decimal, InvalidOperation

from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

from Resources.Notification import create_notification
from models import (
    db,
    User,
    Chama,
    Membership,
    Loan,
    LoanRepayment,
    AuditLog,
    AuditAction,
    MembershipRole,
    MembershipStatus,
    LoanStatus,
    NotificationType,
)


# =========================================================
# HELPERS
# =========================================================

def get_current_user():
    identity = get_jwt_identity()
    if not identity:
        return None

    try:
        user_id = int(identity)
    except (ValueError, TypeError):
        return None

    return User.query.get(user_id)


def get_chama_by_id(chama_id):
    return Chama.query.get(chama_id)


def get_active_membership(user_id, chama_id):
    return Membership.query.filter_by(
        user_id=user_id,
        chama_id=chama_id,
        status=MembershipStatus.ACTIVE,
    ).first()


def require_chama_membership(current_user, chama_id):
    if not current_user:
        return None, ({"message": "User not found."}, 404)

    if not current_user.is_active_account:
        return None, ({"message": "Inactive account cannot access chama resources."}, 403)

    chama = get_chama_by_id(chama_id)
    if not chama:
        return None, ({"message": "Chama not found."}, 404)

    membership = get_active_membership(current_user.id, chama_id)
    if not membership:
        return None, ({"message": "Access denied. You are not a member of this chama."}, 403)

    return (chama, membership), None


def require_finance_roles(current_user, chama_id):
    result, error = require_chama_membership(current_user, chama_id)
    if error:
        return None, error

    chama, membership = result

    if membership.role not in {MembershipRole.ADMIN, MembershipRole.TREASURER}:
        return None, ({"message": "Only admin or treasurer can perform this loan action."}, 403)

    return (chama, membership), None


def parse_amount(value):
    try:
        amount = Decimal(str(value))
        if amount <= 0:
            return None
        return amount.quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError, TypeError):
        return None


def parse_non_negative_amount(value):
    try:
        amount = Decimal(str(value))
        if amount < 0:
            return None
        return amount.quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError, TypeError):
        return None


def parse_optional_date(value, field_name="date"):
    if value in [None, ""]:
        return None, None
    try:
        return datetime.fromisoformat(value), None
    except ValueError:
        return None, {"message": f"Invalid {field_name}. Use ISO format."}


def parse_required_date(value, field_name="date"):
    if value in [None, ""]:
        return None, {"message": f"{field_name} cannot be empty."}
    try:
        return datetime.fromisoformat(value), None
    except ValueError:
        return None, {"message": f"Invalid {field_name}. Use ISO format."}


def normalize_loan_status(value):
    if not value:
        return None

    value = value.strip().lower()
    for status in LoanStatus:
        if status.value == value:
            return status

    return None


def can_view_loan(current_user, membership, loan):
    if membership.role in {MembershipRole.ADMIN, MembershipRole.TREASURER}:
        return True
    return loan.borrower_user_id == current_user.id


def audit_log(
    action,
    actor_user_id=None,
    target_user_id=None,
    chama_id=None,
    loan_id=None,
    membership_id=None,
    description=None,
    old_values=None,
    new_values=None,
    metadata_json=None,
):
    try:
        AuditLog.log(
            action=action,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            chama_id=chama_id,
            loan_id=loan_id,
            membership_id=membership_id,
            description=description,
            old_values=old_values,
            new_values=new_values,
            metadata_json=metadata_json,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception:
        pass


def loan_dict(loan):
    return {
        "id": loan.id,
        "chama_id": loan.chama_id,
        "borrower_user_id": loan.borrower_user_id,
        "borrower_name": loan.borrower.full_name if loan.borrower else None,
        "borrower_username": loan.borrower.username if loan.borrower else None,
        "principal_amount": float(loan.principal_amount) if loan.principal_amount is not None else None,
        "interest_rate": float(loan.interest_rate) if loan.interest_rate is not None else None,
        "total_amount_due": float(loan.total_amount_due) if loan.total_amount_due is not None else None,
        "amount_repaid": float(loan.amount_repaid) if loan.amount_repaid is not None else None,
        "balance": float(loan.balance) if loan.balance is not None else None,
        "purpose": loan.purpose,
        "status": loan.status.value if loan.status else None,
        "applied_at": loan.applied_at.isoformat() if loan.applied_at else None,
        "approved_at": loan.approved_at.isoformat() if loan.approved_at else None,
        "disbursed_at": loan.disbursed_at.isoformat() if loan.disbursed_at else None,
        "due_date": loan.due_date.isoformat() if loan.due_date else None,
        "approved_by_user_id": loan.approved_by_user_id,
        "rejected_by_user_id": loan.rejected_by_user_id,
        "rejection_reason": loan.rejection_reason,
        "created_at": loan.created_at.isoformat() if loan.created_at else None,
        "updated_at": loan.updated_at.isoformat() if loan.updated_at else None,
    }


def repayment_dict(repayment):
    return {
        "id": repayment.id,
        "loan_id": repayment.loan_id,
        "amount": float(repayment.amount) if repayment.amount is not None else None,
        "payment_date": repayment.payment_date.isoformat() if repayment.payment_date else None,
        "recorded_by_user_id": repayment.recorded_by_user_id,
        "recorded_by_name": repayment.recorded_by.full_name if repayment.recorded_by else None,
        "payment_method": repayment.payment_method,
        "reference_code": repayment.reference_code,
        "notes": repayment.notes,
        "created_at": repayment.created_at.isoformat() if repayment.created_at else None,
        "updated_at": repayment.updated_at.isoformat() if repayment.updated_at else None,
    }


# =========================================================
# RESOURCES
# =========================================================

class ChamaLoansResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        query = Loan.query.filter(Loan.chama_id == chama.id)

        borrower_user_id = request.args.get("borrower_user_id", type=int)
        status = request.args.get("status", type=str)

        is_finance_user = membership.role in {MembershipRole.ADMIN, MembershipRole.TREASURER}

        if is_finance_user:
            if borrower_user_id:
                target_membership = Membership.query.filter_by(
                    user_id=borrower_user_id,
                    chama_id=chama.id,
                ).first()
                if not target_membership:
                    return {"message": "The requested user does not belong to this chama."}, 400
                query = query.filter(Loan.borrower_user_id == borrower_user_id)
        else:
            query = query.filter(Loan.borrower_user_id == current_user.id)

        if status:
            normalized_status = normalize_loan_status(status)
            if not normalized_status:
                return {"message": "Invalid loan status."}, 400
            query = query.filter(Loan.status == normalized_status)

        loans = query.order_by(Loan.created_at.desc(), Loan.id.desc()).all()

        return {
            "message": "Loans retrieved successfully.",
            "count": len(loans),
            "loans": [loan_dict(loan) for loan in loans],
        }, 200

    @jwt_required()
    def post(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        data = request.get_json() or {}

        principal_amount = parse_amount(data.get("principal_amount"))
        interest_rate = parse_non_negative_amount(data.get("interest_rate", 0))
        purpose = data.get("purpose")
        due_date_raw = data.get("due_date")

        if principal_amount is None:
            return {"message": "A valid positive principal_amount is required."}, 400

        if interest_rate is None:
            return {"message": "Invalid interest_rate."}, 400

        due_date, due_date_error = parse_optional_date(due_date_raw, "due_date")
        if due_date_error:
            return due_date_error, 400

        try:
            loan = Loan(
                chama_id=chama.id,
                borrower_user_id=current_user.id,
                principal_amount=principal_amount,
                interest_rate=interest_rate,
                purpose=purpose,
                status=LoanStatus.PENDING,
                applied_at=datetime.utcnow(),
                due_date=due_date,
            )
            loan.calculate_total_due()

            db.session.add(loan)
            db.session.flush()

            create_notification(
                user_id=current_user.id,
                chama_id=chama.id,
                title="Loan application submitted",
                message=f"Your loan application in {chama.name} has been submitted successfully.",
                notification_type=NotificationType.LOAN,
                action_url=f"/chamas/{chama.id}/loans/{loan.id}",
                metadata_json={"loan_id": loan.id, "status": LoanStatus.PENDING.value},
            )

            db.session.commit()

            audit_log(
                action=AuditAction.LOAN_APPLIED,
                actor_user_id=current_user.id,
                target_user_id=current_user.id,
                chama_id=chama.id,
                loan_id=loan.id,
                membership_id=membership.id,
                description="Member applied for a loan.",
                new_values=loan_dict(loan),
            )

            return {
                "message": "Loan application submitted successfully.",
                "loan": loan_dict(loan),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error submitting loan application: {str(e)}"}, 500


class MyLoansResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        loans = (
            Loan.query
            .filter_by(chama_id=chama.id, borrower_user_id=current_user.id)
            .order_by(Loan.created_at.desc(), Loan.id.desc())
            .all()
        )

        return {
            "message": "My loans retrieved successfully.",
            "count": len(loans),
            "loans": [loan_dict(loan) for loan in loans],
        }, 200


class LoanDetailResource(Resource):
    @jwt_required()
    def get(self, chama_id, loan_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        loan = Loan.query.filter_by(id=loan_id, chama_id=chama.id).first()

        if not loan:
            return {"message": "Loan not found."}, 404

        if not can_view_loan(current_user, membership, loan):
            return {"message": "You are not allowed to view this loan."}, 403

        return {
            "message": "Loan retrieved successfully.",
            "loan": loan_dict(loan),
        }, 200

    @jwt_required()
    def patch(self, chama_id, loan_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        loan = Loan.query.filter_by(id=loan_id, chama_id=chama.id).first()

        if not loan:
            return {"message": "Loan not found."}, 404

        if loan.status not in {LoanStatus.PENDING, LoanStatus.APPROVED}:
            return {"message": "Only pending or approved loans can be updated here."}, 400

        data = request.get_json() or {}
        old_values = loan_dict(loan)

        if "principal_amount" in data:
            amount = parse_amount(data.get("principal_amount"))
            if amount is None:
                return {"message": "A valid positive principal_amount is required."}, 400
            loan.principal_amount = amount

        if "interest_rate" in data:
            rate = parse_non_negative_amount(data.get("interest_rate"))
            if rate is None:
                return {"message": "Invalid interest_rate."}, 400
            loan.interest_rate = rate

        if "purpose" in data:
            loan.purpose = data.get("purpose")

        if "due_date" in data:
            due_date, due_date_error = parse_optional_date(data.get("due_date"), "due_date")
            if due_date_error:
                return due_date_error, 400
            loan.due_date = due_date

        loan.calculate_total_due()

        try:
            db.session.commit()

            create_notification(
                user_id=loan.borrower_user_id,
                chama_id=chama.id,
                title="Loan updated",
                message=f"Your loan in {chama.name} has been updated.",
                notification_type=NotificationType.LOAN,
                action_url=f"/chamas/{chama.id}/loans/{loan.id}",
                metadata_json={"loan_id": loan.id, "status": loan.status.value},
            )

            audit_log(
                action=AuditAction.LOAN_UPDATED,
                actor_user_id=current_user.id,
                target_user_id=loan.borrower_user_id,
                chama_id=chama.id,
                loan_id=loan.id,
                membership_id=actor_membership.id,
                description="Loan updated.",
                old_values=old_values,
                new_values=loan_dict(loan),
            )

            return {
                "message": "Loan updated successfully.",
                "loan": loan_dict(loan),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error updating loan: {str(e)}"}, 500

    @jwt_required()
    def delete(self, chama_id, loan_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        loan = Loan.query.filter_by(id=loan_id, chama_id=chama.id).first()

        if not loan:
            return {"message": "Loan not found."}, 404

        if loan.status != LoanStatus.PENDING:
            return {"message": "Only pending loans can be deleted."}, 400

        old_values = loan_dict(loan)
        borrower_user_id = loan.borrower_user_id

        try:
            create_notification(
                user_id=borrower_user_id,
                chama_id=chama.id,
                title="Loan deleted",
                message=f"Your pending loan in {chama.name} was deleted.",
                notification_type=NotificationType.LOAN,
                action_url=f"/chamas/{chama.id}/loans",
                metadata_json={"loan_id": loan_id, "status": "deleted"},
            )

            db.session.delete(loan)
            db.session.commit()

            audit_log(
                action=AuditAction.LOAN_DELETED,
                actor_user_id=current_user.id,
                target_user_id=borrower_user_id,
                chama_id=chama.id,
                loan_id=loan_id,
                membership_id=actor_membership.id,
                description="Pending loan deleted.",
                old_values=old_values,
                new_values=None,
                metadata_json={"deleted_loan_id": loan_id},
            )

            return {"message": "Loan deleted successfully."}, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error deleting loan: {str(e)}"}, 500


class LoanApprovalResource(Resource):
    @jwt_required()
    def patch(self, chama_id, loan_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        loan = Loan.query.filter_by(id=loan_id, chama_id=chama.id).first()

        if not loan:
            return {"message": "Loan not found."}, 404

        if loan.status != LoanStatus.PENDING:
            return {"message": "Only pending loans can be approved."}, 400

        old_values = loan_dict(loan)

        loan.status = LoanStatus.APPROVED
        loan.approved_at = datetime.utcnow()
        loan.approved_by_user_id = current_user.id
        loan.rejected_by_user_id = None
        loan.rejection_reason = None

        try:
            create_notification(
                user_id=loan.borrower_user_id,
                chama_id=chama.id,
                title="Loan approved",
                message=f"Your loan in {chama.name} has been approved.",
                notification_type=NotificationType.LOAN,
                action_url=f"/chamas/{chama.id}/loans/{loan.id}",
                metadata_json={"loan_id": loan.id, "status": LoanStatus.APPROVED.value},
            )

            db.session.commit()

            audit_log(
                action=AuditAction.LOAN_APPROVED,
                actor_user_id=current_user.id,
                target_user_id=loan.borrower_user_id,
                chama_id=chama.id,
                loan_id=loan.id,
                membership_id=actor_membership.id,
                description="Loan approved.",
                old_values=old_values,
                new_values=loan_dict(loan),
            )

            return {
                "message": "Loan approved successfully.",
                "loan": loan_dict(loan),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error approving loan: {str(e)}"}, 500


class LoanRejectionResource(Resource):
    @jwt_required()
    def patch(self, chama_id, loan_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        loan = Loan.query.filter_by(id=loan_id, chama_id=chama.id).first()

        if not loan:
            return {"message": "Loan not found."}, 404

        if loan.status != LoanStatus.PENDING:
            return {"message": "Only pending loans can be rejected."}, 400

        data = request.get_json() or {}
        reason = data.get("reason")
        old_values = loan_dict(loan)

        loan.status = LoanStatus.REJECTED
        loan.rejected_by_user_id = current_user.id
        loan.rejection_reason = reason
        loan.approved_at = None
        loan.approved_by_user_id = None
        loan.disbursed_at = None

        try:
            create_notification(
                user_id=loan.borrower_user_id,
                chama_id=chama.id,
                title="Loan rejected",
                message=f"Your loan in {chama.name} was rejected.",
                notification_type=NotificationType.LOAN,
                action_url=f"/chamas/{chama.id}/loans/{loan.id}",
                metadata_json={
                    "loan_id": loan.id,
                    "status": LoanStatus.REJECTED.value,
                    "reason": reason,
                },
            )

            db.session.commit()

            audit_log(
                action=AuditAction.LOAN_REJECTED,
                actor_user_id=current_user.id,
                target_user_id=loan.borrower_user_id,
                chama_id=chama.id,
                loan_id=loan.id,
                membership_id=actor_membership.id,
                description="Loan rejected.",
                old_values=old_values,
                new_values=loan_dict(loan),
            )

            return {
                "message": "Loan rejected successfully.",
                "loan": loan_dict(loan),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error rejecting loan: {str(e)}"}, 500


class LoanDisbursementResource(Resource):
    @jwt_required()
    def patch(self, chama_id, loan_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        loan = Loan.query.filter_by(id=loan_id, chama_id=chama.id).first()

        if not loan:
            return {"message": "Loan not found."}, 404

        if loan.status != LoanStatus.APPROVED:
            return {"message": "Only approved loans can be disbursed."}, 400

        if loan.amount_repaid > 0:
            return {
                "message": "Cannot disburse a loan that already has recorded repayments."
            }, 400

        if loan.disbursed_at is not None:
            return {"message": "Loan has already been disbursed."}, 400

        old_values = loan_dict(loan)

        loan.status = LoanStatus.DISBURSED
        loan.disbursed_at = datetime.utcnow()

        try:
            create_notification(
                user_id=loan.borrower_user_id,
                chama_id=chama.id,
                title="Loan disbursed",
                message=f"Your loan in {chama.name} has been disbursed.",
                notification_type=NotificationType.LOAN,
                action_url=f"/chamas/{chama.id}/loans/{loan.id}",
                metadata_json={"loan_id": loan.id, "status": LoanStatus.DISBURSED.value},
            )

            db.session.commit()

            audit_log(
                action=AuditAction.LOAN_DISBURSED,
                actor_user_id=current_user.id,
                target_user_id=loan.borrower_user_id,
                chama_id=chama.id,
                loan_id=loan.id,
                membership_id=actor_membership.id,
                description="Loan disbursed.",
                old_values=old_values,
                new_values=loan_dict(loan),
            )

            return {
                "message": "Loan disbursed successfully.",
                "loan": loan_dict(loan),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error disbursing loan: {str(e)}"}, 500


class LoanRepaymentsResource(Resource):
    @jwt_required()
    def get(self, chama_id, loan_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        loan = Loan.query.filter_by(id=loan_id, chama_id=chama.id).first()

        if not loan:
            return {"message": "Loan not found."}, 404

        if not can_view_loan(current_user, membership, loan):
            return {"message": "You are not allowed to view this loan repayments history."}, 403

        repayments = (
            LoanRepayment.query
            .filter_by(loan_id=loan.id)
            .order_by(LoanRepayment.payment_date.desc(), LoanRepayment.id.desc())
            .all()
        )

        return {
            "message": "Loan repayments retrieved successfully.",
            "loan": loan_dict(loan),
            "count": len(repayments),
            "repayments": [repayment_dict(r) for r in repayments],
        }, 200

    @jwt_required()
    def post(self, chama_id, loan_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        loan = Loan.query.filter_by(id=loan_id, chama_id=chama.id).first()

        if not loan:
            return {"message": "Loan not found."}, 404

        if loan.status not in {LoanStatus.DISBURSED, LoanStatus.PARTIALLY_REPAID}:
            return {"message": "Repayment can only be recorded for disbursed or partially repaid loans."}, 400

        data = request.get_json() or {}

        amount = parse_amount(data.get("amount"))
        payment_method = (data.get("payment_method") or "").strip() or None
        reference_code = (data.get("reference_code") or "").strip() or None
        notes = data.get("notes")
        payment_date_raw = data.get("payment_date")

        if amount is None:
            return {"message": "A valid positive amount is required."}, 400

        payment_date = datetime.utcnow()
        if payment_date_raw:
            payment_date, payment_date_error = parse_required_date(payment_date_raw, "payment_date")
            if payment_date_error:
                return payment_date_error, 400

        old_values = loan_dict(loan)

        try:
            repayment = LoanRepayment(
                loan=loan,
                amount=amount,
                payment_date=payment_date,
                recorded_by_user_id=current_user.id,
                payment_method=payment_method,
                reference_code=reference_code,
                notes=notes,
            )

            db.session.add(repayment)
            db.session.flush()

            loan.refresh_repayment_status()

            create_notification(
                user_id=loan.borrower_user_id,
                chama_id=chama.id,
                title="Loan repayment recorded",
                message=f"A repayment has been recorded for your loan in {chama.name}.",
                notification_type=NotificationType.LOAN,
                action_url=f"/chamas/{chama.id}/loans/{loan.id}",
                metadata_json={
                    "loan_id": loan.id,
                    "repayment_id": repayment.id,
                    "status": loan.status.value,
                },
            )

            db.session.commit()

            audit_log(
                action=AuditAction.LOAN_REPAYMENT_RECORDED,
                actor_user_id=current_user.id,
                target_user_id=loan.borrower_user_id,
                chama_id=chama.id,
                loan_id=loan.id,
                membership_id=actor_membership.id,
                description="Loan repayment recorded.",
                old_values=old_values,
                new_values={
                    "loan": loan_dict(loan),
                    "repayment": repayment_dict(repayment),
                },
            )

            return {
                "message": "Loan repayment recorded successfully.",
                "loan": loan_dict(loan),
                "repayment": repayment_dict(repayment),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error recording repayment: {str(e)}"}, 500