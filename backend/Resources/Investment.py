from datetime import datetime
from decimal import Decimal, InvalidOperation

from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import (
    db,
    User,
    Chama,
    Membership,
    Investment,
    InvestmentReturn,
    AuditLog,
    AuditAction,
    MembershipRole,
    MembershipStatus,
    InvestmentStatus,
    InvestmentType,
    ReturnType,
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
        return None, ({"message": "Access denied. You are not an active member of this chama."}, 403)

    return (chama, membership), None


def require_finance_roles(current_user, chama_id):
    result, error = require_chama_membership(current_user, chama_id)
    if error:
        return None, error

    chama, membership = result
    if membership.role not in {MembershipRole.ADMIN, MembershipRole.TREASURER}:
        return None, ({"message": "Only admin or treasurer can perform this investment action."}, 403)

    return (chama, membership), None


def parse_amount(value):
    try:
        amount = Decimal(str(value))
        if amount < 0:
            return None
        return amount.quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError, ValueError):
        return None


def parse_required_positive_amount(value, field_name="amount"):
    try:
        amount = Decimal(str(value))
        if amount <= 0:
            return None, {"message": f"{field_name} must be a positive number."}
        return amount.quantize(Decimal("0.01")), None
    except (InvalidOperation, TypeError, ValueError):
        return None, {"message": f"Invalid {field_name}."}


def parse_optional_date(value, field_name="date"):
    if value in [None, ""]:
        return None, None
    try:
        return datetime.fromisoformat(value), None
    except ValueError:
        return None, {"message": f"Invalid {field_name}. Use ISO format."}


def normalize_investment_status(value):
    if not value:
        return None
    value = value.strip().lower()
    for status in InvestmentStatus:
        if status.value == value:
            return status
    return None


def normalize_investment_type(value):
    if not value:
        return None
    value = value.strip().lower()
    for item in InvestmentType:
        if item.value == value:
            return item
    return None


def normalize_return_type(value):
    if not value:
        return None
    value = value.strip().lower()
    for item in ReturnType:
        if item.value == value:
            return item
    return None


def audit_log(
    action,
    actor_user_id=None,
    target_user_id=None,
    chama_id=None,
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
            description=description,
            old_values=old_values,
            new_values=new_values,
            metadata_json=metadata_json,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception:
        pass


def investment_return_dict(item):
    return {
        "id": item.id,
        "investment_id": item.investment_id,
        "amount": float(item.amount) if item.amount is not None else None,
        "return_type": item.return_type.value if item.return_type else None,
        "return_date": item.return_date.isoformat() if item.return_date else None,
        "notes": item.notes,
        "recorded_by_user_id": item.recorded_by_user_id,
        "recorded_by_name": item.recorded_by.full_name if item.recorded_by else None,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def investment_dict(investment, include_returns=False):
    data = {
        "id": investment.id,
        "chama_id": investment.chama_id,
        "name": investment.name,
        "description": investment.description,
        "investment_type": investment.investment_type.value if investment.investment_type else None,
        "status": investment.status.value if investment.status else None,
        "principal_amount": float(investment.principal_amount) if investment.principal_amount is not None else None,
        "current_value": float(investment.current_value) if investment.current_value is not None else None,
        "expected_return_rate": float(investment.expected_return_rate) if investment.expected_return_rate is not None else None,
        "invested_at": investment.invested_at.isoformat() if investment.invested_at else None,
        "maturity_date": investment.maturity_date.isoformat() if investment.maturity_date else None,
        "closed_at": investment.closed_at.isoformat() if investment.closed_at else None,
        "created_by_user_id": investment.created_by_user_id,
        "created_by_name": investment.created_by.full_name if investment.created_by else None,
        "approved_by_user_id": investment.approved_by_user_id,
        "approved_by_name": investment.approved_by.full_name if investment.approved_by else None,
        "total_returns": investment.total_returns,
        "profit_or_loss": investment.profit_or_loss,
        "roi_percentage": investment.roi_percentage,
        "created_at": investment.created_at.isoformat() if investment.created_at else None,
        "updated_at": investment.updated_at.isoformat() if investment.updated_at else None,
    }

    if include_returns:
        data["returns"] = [investment_return_dict(r) for r in investment.returns]

    return data


# =========================================================
# RESOURCES
# =========================================================

class ChamaInvestmentsResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        query = Investment.query.filter_by(chama_id=chama.id)

        status = request.args.get("status", type=str)
        investment_type = request.args.get("investment_type", type=str)

        if status:
            normalized_status = normalize_investment_status(status)
            if not normalized_status:
                return {"message": "Invalid investment status."}, 400
            query = query.filter(Investment.status == normalized_status)

        if investment_type:
            normalized_type = normalize_investment_type(investment_type)
            if not normalized_type:
                return {"message": "Invalid investment type."}, 400
            query = query.filter(Investment.investment_type == normalized_type)

        investments = query.order_by(Investment.created_at.desc(), Investment.id.desc()).all()

        return {
            "message": "Investments retrieved successfully.",
            "count": len(investments),
            "investments": [investment_dict(i) for i in investments],
        }, 200

    @jwt_required()
    def post(self, chama_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        data = request.get_json() or {}

        name = (data.get("name") or "").strip()
        description = data.get("description")
        investment_type = normalize_investment_type(data.get("investment_type") or "other")
        principal_amount, amount_error = parse_required_positive_amount(data.get("principal_amount"), "principal_amount")
        current_value = parse_amount(data.get("current_value", 0))
        expected_return_rate = parse_amount(data.get("expected_return_rate")) if data.get("expected_return_rate") is not None else None
        invested_at, invested_at_error = parse_optional_date(data.get("invested_at"), "invested_at")
        maturity_date, maturity_date_error = parse_optional_date(data.get("maturity_date"), "maturity_date")

        if not name:
            return {"message": "name is required."}, 400
        if not investment_type:
            return {"message": "Invalid investment_type."}, 400
        if amount_error:
            return amount_error, 400
        if data.get("current_value") is not None and current_value is None:
            return {"message": "Invalid current_value."}, 400
        if data.get("expected_return_rate") is not None and expected_return_rate is None:
            return {"message": "Invalid expected_return_rate."}, 400
        if invested_at_error:
            return invested_at_error, 400
        if maturity_date_error:
            return maturity_date_error, 400
        if invested_at and maturity_date and maturity_date <= invested_at:
            return {"message": "maturity_date must be later than invested_at."}, 400

        try:
            investment = Investment(
                chama_id=chama.id,
                name=name,
                description=description,
                investment_type=investment_type,
                status=InvestmentStatus.PROPOSED,
                principal_amount=principal_amount,
                current_value=current_value if current_value is not None else principal_amount,
                expected_return_rate=expected_return_rate,
                invested_at=invested_at,
                maturity_date=maturity_date,
                created_by_user_id=current_user.id,
            )

            db.session.add(investment)
            db.session.commit()

            audit_log(
                action=AuditAction.INVESTMENT_CREATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Investment created.",
                new_values=investment_dict(investment),
            )

            return {
                "message": "Investment created successfully.",
                "investment": investment_dict(investment),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating investment: {str(e)}"}, 500


class InvestmentDetailResource(Resource):
    @jwt_required()
    def get(self, chama_id, investment_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        investment = Investment.query.filter_by(id=investment_id, chama_id=chama.id).first()
        if not investment:
            return {"message": "Investment not found."}, 404

        return {
            "message": "Investment retrieved successfully.",
            "investment": investment_dict(investment, include_returns=True),
        }, 200

    @jwt_required()
    def patch(self, chama_id, investment_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        investment = Investment.query.filter_by(id=investment_id, chama_id=chama.id).first()
        if not investment:
            return {"message": "Investment not found."}, 404

        if investment.status in {InvestmentStatus.CLOSED, InvestmentStatus.CANCELLED}:
            return {"message": "Closed or cancelled investments cannot be updated."}, 400

        old_values = investment_dict(investment, include_returns=True)
        data = request.get_json() or {}

        if "name" in data:
            name = (data.get("name") or "").strip()
            if not name:
                return {"message": "name cannot be empty."}, 400
            investment.name = name

        if "description" in data:
            investment.description = data.get("description")

        if "investment_type" in data:
            normalized_type = normalize_investment_type(data.get("investment_type"))
            if not normalized_type:
                return {"message": "Invalid investment_type."}, 400
            investment.investment_type = normalized_type

        if "principal_amount" in data:
            principal_amount, amount_error = parse_required_positive_amount(data.get("principal_amount"), "principal_amount")
            if amount_error:
                return amount_error, 400
            investment.principal_amount = principal_amount

        if "current_value" in data:
            current_value = parse_amount(data.get("current_value"))
            if current_value is None:
                return {"message": "Invalid current_value."}, 400
            investment.current_value = current_value

        if "expected_return_rate" in data:
            if data.get("expected_return_rate") in [None, ""]:
                investment.expected_return_rate = None
            else:
                expected_return_rate = parse_amount(data.get("expected_return_rate"))
                if expected_return_rate is None:
                    return {"message": "Invalid expected_return_rate."}, 400
                investment.expected_return_rate = expected_return_rate

        if "invested_at" in data:
            invested_at, invested_at_error = parse_optional_date(data.get("invested_at"), "invested_at")
            if invested_at_error:
                return invested_at_error, 400
            investment.invested_at = invested_at

        if "maturity_date" in data:
            maturity_date, maturity_date_error = parse_optional_date(data.get("maturity_date"), "maturity_date")
            if maturity_date_error:
                return maturity_date_error, 400
            investment.maturity_date = maturity_date

        if investment.invested_at and investment.maturity_date and investment.maturity_date <= investment.invested_at:
            return {"message": "maturity_date must be later than invested_at."}, 400

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.INVESTMENT_UPDATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Investment updated.",
                old_values=old_values,
                new_values=investment_dict(investment, include_returns=True),
            )

            return {
                "message": "Investment updated successfully.",
                "investment": investment_dict(investment, include_returns=True),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error updating investment: {str(e)}"}, 500

    @jwt_required()
    def delete(self, chama_id, investment_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        investment = Investment.query.filter_by(id=investment_id, chama_id=chama.id).first()
        if not investment:
            return {"message": "Investment not found."}, 404

        if investment.status not in {InvestmentStatus.PROPOSED, InvestmentStatus.CANCELLED}:
            return {"message": "Only proposed or cancelled investments can be deleted."}, 400

        old_values = investment_dict(investment, include_returns=True)

        try:
            db.session.delete(investment)
            db.session.commit()

            audit_log(
                action=AuditAction.INVESTMENT_DELETED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Investment deleted.",
                old_values=old_values,
                new_values=None,
            )

            return {"message": "Investment deleted successfully."}, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error deleting investment: {str(e)}"}, 500


class InvestmentApproveResource(Resource):
    @jwt_required()
    def patch(self, chama_id, investment_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        investment = Investment.query.filter_by(id=investment_id, chama_id=chama.id).first()
        if not investment:
            return {"message": "Investment not found."}, 404

        if investment.status != InvestmentStatus.PROPOSED:
            return {"message": "Only proposed investments can be approved."}, 400

        old_values = investment_dict(investment)

        investment.status = InvestmentStatus.ACTIVE
        investment.approved_by_user_id = current_user.id
        investment.invested_at = investment.invested_at or datetime.utcnow()

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.INVESTMENT_APPROVED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Investment approved.",
                old_values=old_values,
                new_values=investment_dict(investment),
            )

            return {
                "message": "Investment approved successfully.",
                "investment": investment_dict(investment),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error approving investment: {str(e)}"}, 500


class InvestmentCloseResource(Resource):
    @jwt_required()
    def patch(self, chama_id, investment_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        investment = Investment.query.filter_by(id=investment_id, chama_id=chama.id).first()
        if not investment:
            return {"message": "Investment not found."}, 404

        if investment.status != InvestmentStatus.ACTIVE:
            return {"message": "Only active investments can be closed."}, 400

        old_values = investment_dict(investment)
        data = request.get_json() or {}

        if "current_value" in data:
            current_value = parse_amount(data.get("current_value"))
            if current_value is None:
                return {"message": "Invalid current_value."}, 400
            investment.current_value = current_value

        investment.status = InvestmentStatus.CLOSED
        investment.closed_at = datetime.utcnow()

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.INVESTMENT_CLOSED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Investment closed.",
                old_values=old_values,
                new_values=investment_dict(investment, include_returns=True),
            )

            return {
                "message": "Investment closed successfully.",
                "investment": investment_dict(investment, include_returns=True),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error closing investment: {str(e)}"}, 500


class InvestmentCancelResource(Resource):
    @jwt_required()
    def patch(self, chama_id, investment_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        investment = Investment.query.filter_by(id=investment_id, chama_id=chama.id).first()
        if not investment:
            return {"message": "Investment not found."}, 404

        if investment.status != InvestmentStatus.PROPOSED:
            return {"message": "Only proposed investments can be cancelled."}, 400

        old_values = investment_dict(investment)

        investment.status = InvestmentStatus.CANCELLED
        investment.approved_by_user_id = None
        investment.invested_at = None

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.INVESTMENT_CANCELLED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Investment cancelled.",
                old_values=old_values,
                new_values=investment_dict(investment),
            )

            return {
                "message": "Investment cancelled successfully.",
                "investment": investment_dict(investment),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error cancelling investment: {str(e)}"}, 500


class InvestmentReturnResource(Resource):
    @jwt_required()
    def get(self, chama_id, investment_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        investment = Investment.query.filter_by(id=investment_id, chama_id=chama.id).first()
        if not investment:
            return {"message": "Investment not found."}, 404

        returns = (
            InvestmentReturn.query
            .filter_by(investment_id=investment.id)
            .order_by(InvestmentReturn.return_date.desc(), InvestmentReturn.id.desc())
            .all()
        )

        return {
            "message": "Investment returns retrieved successfully.",
            "investment": investment_dict(investment),
            "count": len(returns),
            "returns": [investment_return_dict(r) for r in returns],
        }, 200

    @jwt_required()
    def post(self, chama_id, investment_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        investment = Investment.query.filter_by(id=investment_id, chama_id=chama.id).first()
        if not investment:
            return {"message": "Investment not found."}, 404

        if investment.status not in {InvestmentStatus.ACTIVE, InvestmentStatus.CLOSED}:
            return {"message": "Returns can only be recorded for active or closed investments."}, 400

        data = request.get_json() or {}

        amount, amount_error = parse_required_positive_amount(data.get("amount"), "amount")
        return_type = normalize_return_type(data.get("return_type") or "other")
        return_date, return_date_error = parse_optional_date(data.get("return_date"), "return_date")
        notes = data.get("notes")

        if amount_error:
            return amount_error, 400
        if not return_type:
            return {"message": "Invalid return_type."}, 400
        if return_date_error:
            return return_date_error, 400

        try:
            item = InvestmentReturn(
                investment_id=investment.id,
                amount=amount,
                return_type=return_type,
                return_date=return_date or datetime.utcnow(),
                notes=notes,
                recorded_by_user_id=current_user.id,
            )

            db.session.add(item)
            db.session.commit()

            audit_log(
                action=AuditAction.INVESTMENT_RETURN_RECORDED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Investment return recorded.",
                new_values=investment_return_dict(item),
            )

            return {
                "message": "Investment return recorded successfully.",
                "investment": investment_dict(investment, include_returns=True),
                "return": investment_return_dict(item),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error recording investment return: {str(e)}"}, 500


class InvestmentSummaryResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        investments = Investment.query.filter_by(chama_id=chama.id).all()

        total_principal = round(sum(float(i.principal_amount or 0) for i in investments), 2)
        total_current_value = round(sum(float(i.current_value or 0) for i in investments), 2)
        total_returns = round(sum(float(i.total_returns or 0) for i in investments), 2)
        total_profit_or_loss = round(sum(float(i.profit_or_loss or 0) for i in investments), 2)

        by_status = {}
        for status in InvestmentStatus:
            by_status[status.value] = Investment.query.filter_by(chama_id=chama.id, status=status).count()

        return {
            "message": "Investment summary retrieved successfully.",
            "summary": {
                "chama_id": chama.id,
                "total_investments": len(investments),
                "total_principal": total_principal,
                "total_current_value": total_current_value,
                "total_returns": total_returns,
                "total_profit_or_loss": total_profit_or_loss,
                "by_status": by_status,
            },
        }, 200