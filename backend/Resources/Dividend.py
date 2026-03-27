from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import (
    db,
    User,
    Chama,
    Membership,
    Contribution,
    Dividend,
    DividendAllocation,
    AuditLog,
    AuditAction,
    MembershipRole,
    MembershipStatus,
    DividendStatus,
    DividendDistributionMethod,
    DividendAllocationStatus,
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
        return None, ({"message": "Only admin or treasurer can perform this dividend action."}, 403)

    return (chama, membership), None


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


def normalize_dividend_status(value):
    if not value:
        return None
    value = value.strip().lower()
    for item in DividendStatus:
        if item.value == value:
            return item
    return None


def normalize_distribution_method(value):
    if not value:
        return None
    value = value.strip().lower()
    for item in DividendDistributionMethod:
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


def allocation_dict(item):
    return {
        "id": item.id,
        "dividend_id": item.dividend_id,
        "user_id": item.user_id,
        "member_name": item.user.full_name if item.user else None,
        "amount": float(item.amount) if item.amount is not None else None,
        "status": item.status.value if item.status else None,
        "paid_at": item.paid_at.isoformat() if item.paid_at else None,
        "paid_by_user_id": item.paid_by_user_id,
        "paid_by_name": item.paid_by.full_name if item.paid_by else None,
        "notes": item.notes,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def dividend_dict(dividend, include_allocations=False):
    data = {
        "id": dividend.id,
        "chama_id": dividend.chama_id,
        "title": dividend.title,
        "description": dividend.description,
        "total_amount": float(dividend.total_amount) if dividend.total_amount is not None else None,
        "status": dividend.status.value if dividend.status else None,
        "distribution_method": dividend.distribution_method.value if dividend.distribution_method else None,
        "distribution_date": dividend.distribution_date.isoformat() if dividend.distribution_date else None,
        "period_start": dividend.period_start.isoformat() if dividend.period_start else None,
        "period_end": dividend.period_end.isoformat() if dividend.period_end else None,
        "created_by_user_id": dividend.created_by_user_id,
        "created_by_name": dividend.created_by.full_name if dividend.created_by else None,
        "approved_by_user_id": dividend.approved_by_user_id,
        "approved_by_name": dividend.approved_by.full_name if dividend.approved_by else None,
        "total_allocated": dividend.total_allocated,
        "total_paid": dividend.total_paid,
        "pending_amount": dividend.pending_amount,
        "created_at": dividend.created_at.isoformat() if dividend.created_at else None,
        "updated_at": dividend.updated_at.isoformat() if dividend.updated_at else None,
    }

    if include_allocations:
        data["allocations"] = [allocation_dict(a) for a in dividend.allocations]

    return data


def split_equal(total_amount, user_ids):
    count = len(user_ids)
    if count == 0:
        return {}

    per_person = (total_amount / Decimal(count)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    allocations = {user_id: per_person for user_id in user_ids}

    allocated_sum = sum(allocations.values(), Decimal("0.00"))
    remainder = total_amount - allocated_sum

    if remainder != Decimal("0.00"):
        last_user_id = user_ids[-1]
        allocations[last_user_id] = (allocations[last_user_id] + remainder).quantize(Decimal("0.01"))

    return allocations


def split_proportional(total_amount, weighted_amounts):
    # weighted_amounts = {user_id: Decimal("...")}
    total_weight = sum(weighted_amounts.values(), Decimal("0.00"))
    if total_weight <= Decimal("0.00"):
        return None

    allocations = {}
    running_total = Decimal("0.00")
    user_ids = list(weighted_amounts.keys())

    for idx, user_id in enumerate(user_ids):
        if idx == len(user_ids) - 1:
            amount = total_amount - running_total
        else:
            ratio = weighted_amounts[user_id] / total_weight
            amount = (total_amount * ratio).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            running_total += amount

        allocations[user_id] = amount.quantize(Decimal("0.01"))

    return allocations


# =========================================================
# RESOURCES
# =========================================================

class ChamaDividendsResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        query = Dividend.query.filter_by(chama_id=chama.id)

        status = request.args.get("status", type=str)
        distribution_method = request.args.get("distribution_method", type=str)

        if status:
            normalized_status = normalize_dividend_status(status)
            if not normalized_status:
                return {"message": "Invalid dividend status."}, 400
            query = query.filter(Dividend.status == normalized_status)

        if distribution_method:
            normalized_method = normalize_distribution_method(distribution_method)
            if not normalized_method:
                return {"message": "Invalid distribution_method."}, 400
            query = query.filter(Dividend.distribution_method == normalized_method)

        dividends = query.order_by(Dividend.created_at.desc(), Dividend.id.desc()).all()

        return {
            "message": "Dividends retrieved successfully.",
            "count": len(dividends),
            "dividends": [dividend_dict(d) for d in dividends],
        }, 200

    @jwt_required()
    def post(self, chama_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        data = request.get_json() or {}

        title = (data.get("title") or "").strip()
        description = data.get("description")
        total_amount, amount_error = parse_required_positive_amount(data.get("total_amount"), "total_amount")
        distribution_method = normalize_distribution_method(data.get("distribution_method") or "equal")
        distribution_date, distribution_date_error = parse_optional_date(data.get("distribution_date"), "distribution_date")
        period_start, period_start_error = parse_optional_date(data.get("period_start"), "period_start")
        period_end, period_end_error = parse_optional_date(data.get("period_end"), "period_end")

        if not title:
            return {"message": "title is required."}, 400
        if amount_error:
            return amount_error, 400
        if not distribution_method:
            return {"message": "Invalid distribution_method."}, 400
        if distribution_date_error:
            return distribution_date_error, 400
        if period_start_error:
            return period_start_error, 400
        if period_end_error:
            return period_end_error, 400
        if period_start and period_end and period_end < period_start:
            return {"message": "period_end cannot be earlier than period_start."}, 400

        try:
            dividend = Dividend(
                chama_id=chama.id,
                title=title,
                description=description,
                total_amount=total_amount,
                status=DividendStatus.DRAFT,
                distribution_method=distribution_method,
                distribution_date=distribution_date,
                period_start=period_start,
                period_end=period_end,
                created_by_user_id=current_user.id,
            )

            db.session.add(dividend)
            db.session.commit()

            audit_log(
                action=AuditAction.DIVIDEND_CREATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Dividend created.",
                new_values=dividend_dict(dividend),
            )

            return {
                "message": "Dividend created successfully.",
                "dividend": dividend_dict(dividend),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating dividend: {str(e)}"}, 500


class DividendDetailResource(Resource):
    @jwt_required()
    def get(self, chama_id, dividend_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        dividend = Dividend.query.filter_by(id=dividend_id, chama_id=chama.id).first()

        if not dividend:
            return {"message": "Dividend not found."}, 404

        return {
            "message": "Dividend retrieved successfully.",
            "dividend": dividend_dict(dividend, include_allocations=True),
        }, 200

    @jwt_required()
    def patch(self, chama_id, dividend_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        dividend = Dividend.query.filter_by(id=dividend_id, chama_id=chama.id).first()

        if not dividend:
            return {"message": "Dividend not found."}, 404

        if dividend.status != DividendStatus.DRAFT:
            return {"message": "Only draft dividends can be updated."}, 400

        old_values = dividend_dict(dividend, include_allocations=True)
        data = request.get_json() or {}

        if "title" in data:
            title = (data.get("title") or "").strip()
            if not title:
                return {"message": "title cannot be empty."}, 400
            dividend.title = title

        if "description" in data:
            dividend.description = data.get("description")

        if "total_amount" in data:
            total_amount, amount_error = parse_required_positive_amount(data.get("total_amount"), "total_amount")
            if amount_error:
                return amount_error, 400
            dividend.total_amount = total_amount

        if "distribution_method" in data:
            method = normalize_distribution_method(data.get("distribution_method"))
            if not method:
                return {"message": "Invalid distribution_method."}, 400
            dividend.distribution_method = method

        if "distribution_date" in data:
            distribution_date, distribution_date_error = parse_optional_date(data.get("distribution_date"), "distribution_date")
            if distribution_date_error:
                return distribution_date_error, 400
            dividend.distribution_date = distribution_date

        if "period_start" in data:
            period_start, period_start_error = parse_optional_date(data.get("period_start"), "period_start")
            if period_start_error:
                return period_start_error, 400
            dividend.period_start = period_start

        if "period_end" in data:
            period_end, period_end_error = parse_optional_date(data.get("period_end"), "period_end")
            if period_end_error:
                return period_end_error, 400
            dividend.period_end = period_end

        if dividend.period_start and dividend.period_end and dividend.period_end < dividend.period_start:
            return {"message": "period_end cannot be earlier than period_start."}, 400

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.DIVIDEND_UPDATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Dividend updated.",
                old_values=old_values,
                new_values=dividend_dict(dividend, include_allocations=True),
            )

            return {
                "message": "Dividend updated successfully.",
                "dividend": dividend_dict(dividend, include_allocations=True),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error updating dividend: {str(e)}"}, 500

    @jwt_required()
    def delete(self, chama_id, dividend_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        dividend = Dividend.query.filter_by(id=dividend_id, chama_id=chama.id).first()

        if not dividend:
            return {"message": "Dividend not found."}, 404

        if dividend.status not in {DividendStatus.DRAFT, DividendStatus.CANCELLED}:
            return {"message": "Only draft or cancelled dividends can be deleted."}, 400

        old_values = dividend_dict(dividend, include_allocations=True)

        try:
            db.session.delete(dividend)
            db.session.commit()

            audit_log(
                action=AuditAction.DIVIDEND_DELETED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Dividend deleted.",
                old_values=old_values,
                new_values=None,
            )

            return {"message": "Dividend deleted successfully."}, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error deleting dividend: {str(e)}"}, 500


class DividendApproveResource(Resource):
    @jwt_required()
    def patch(self, chama_id, dividend_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        dividend = Dividend.query.filter_by(id=dividend_id, chama_id=chama.id).first()

        if not dividend:
            return {"message": "Dividend not found."}, 404

        if dividend.status != DividendStatus.DRAFT:
            return {"message": "Only draft dividends can be approved."}, 400

        old_values = dividend_dict(dividend)
        dividend.status = DividendStatus.APPROVED
        dividend.approved_by_user_id = current_user.id

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.DIVIDEND_APPROVED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Dividend approved.",
                old_values=old_values,
                new_values=dividend_dict(dividend),
            )

            return {
                "message": "Dividend approved successfully.",
                "dividend": dividend_dict(dividend),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error approving dividend: {str(e)}"}, 500


class DividendDistributeResource(Resource):
    @jwt_required()
    def patch(self, chama_id, dividend_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        dividend = Dividend.query.filter_by(id=dividend_id, chama_id=chama.id).first()

        if not dividend:
            return {"message": "Dividend not found."}, 404

        if dividend.status != DividendStatus.APPROVED:
            return {"message": "Only approved dividends can be distributed."}, 400

        if dividend.allocations:
            return {"message": "Dividend has already been distributed."}, 400

        active_memberships = Membership.query.filter_by(
            chama_id=chama.id,
            status=MembershipStatus.ACTIVE,
        ).order_by(Membership.user_id.asc()).all()

        if not active_memberships:
            return {"message": "No active members found for dividend distribution."}, 400

        user_ids = [m.user_id for m in active_memberships]
        total_amount = Decimal(str(dividend.total_amount)).quantize(Decimal("0.01"))

        if dividend.distribution_method == DividendDistributionMethod.EQUAL:
            allocations_map = split_equal(total_amount, user_ids)

        elif dividend.distribution_method == DividendDistributionMethod.PROPORTIONAL_CONTRIBUTION:
            if not dividend.period_start or not dividend.period_end:
                return {
                    "message": "period_start and period_end are required for proportional contribution distribution."
                }, 400

            contributions = (
                Contribution.query
                .filter(
                    Contribution.chama_id == chama.id,
                    Contribution.contribution_date >= dividend.period_start,
                    Contribution.contribution_date <= dividend.period_end,
                    Contribution.user_id.in_(user_ids),
                )
                .all()
            )

            weighted_amounts = {user_id: Decimal("0.00") for user_id in user_ids}
            for contribution in contributions:
                weighted_amounts[contribution.user_id] += Decimal(str(contribution.amount or 0)).quantize(Decimal("0.01"))

            allocations_map = split_proportional(total_amount, weighted_amounts)
            if allocations_map is None:
                return {
                    "message": "Cannot distribute proportionally because there are no contributions in the selected period."
                }, 400

        else:
            return {"message": "Unsupported distribution method."}, 400

        old_values = dividend_dict(dividend, include_allocations=True)

        try:
            for user_id, amount in allocations_map.items():
                allocation = DividendAllocation(
                    dividend_id=dividend.id,
                    user_id=user_id,
                    amount=amount,
                    status=DividendAllocationStatus.PENDING,
                )
                db.session.add(allocation)

            dividend.status = DividendStatus.DISTRIBUTED
            dividend.distribution_date = dividend.distribution_date or datetime.utcnow()

            db.session.commit()

            audit_log(
                action=AuditAction.DIVIDEND_DISTRIBUTED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Dividend distributed to members.",
                old_values=old_values,
                new_values=dividend_dict(dividend, include_allocations=True),
                metadata_json={"allocation_count": len(allocations_map)},
            )

            return {
                "message": "Dividend distributed successfully.",
                "dividend": dividend_dict(dividend, include_allocations=True),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error distributing dividend: {str(e)}"}, 500


class DividendAllocationPaymentResource(Resource):
    @jwt_required()
    def patch(self, chama_id, dividend_id, allocation_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        dividend = Dividend.query.filter_by(id=dividend_id, chama_id=chama.id).first()

        if not dividend:
            return {"message": "Dividend not found."}, 404

        allocation = DividendAllocation.query.filter_by(
            id=allocation_id,
            dividend_id=dividend.id,
        ).first()

        if not allocation:
            return {"message": "Dividend allocation not found."}, 404

        if allocation.status == DividendAllocationStatus.PAID:
            return {"message": "Dividend allocation has already been paid."}, 400

        old_values = allocation_dict(allocation)
        data = request.get_json() or {}

        if "notes" in data:
            allocation.notes = data.get("notes")

        try:
            allocation.mark_paid(paid_by_user_id=current_user.id)
            db.session.commit()

            audit_log(
                action=AuditAction.DIVIDEND_PAYMENT_RECORDED,
                actor_user_id=current_user.id,
                target_user_id=allocation.user_id,
                chama_id=chama.id,
                description="Dividend payment recorded.",
                old_values=old_values,
                new_values=allocation_dict(allocation),
            )

            return {
                "message": "Dividend payment recorded successfully.",
                "allocation": allocation_dict(allocation),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error recording dividend payment: {str(e)}"}, 500


class DividendSummaryResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        dividends = Dividend.query.filter_by(chama_id=chama.id).all()

        total_declared = round(sum(float(d.total_amount or 0) for d in dividends), 2)
        total_allocated = round(sum(float(d.total_allocated or 0) for d in dividends), 2)
        total_paid = round(sum(float(d.total_paid or 0) for d in dividends), 2)
        total_pending = round(sum(float(d.pending_amount or 0) for d in dividends), 2)

        by_status = {}
        for status in DividendStatus:
            by_status[status.value] = Dividend.query.filter_by(chama_id=chama.id, status=status).count()

        return {
            "message": "Dividend summary retrieved successfully.",
            "summary": {
                "chama_id": chama.id,
                "total_dividends": len(dividends),
                "total_declared": total_declared,
                "total_allocated": total_allocated,
                "total_paid": total_paid,
                "total_pending": total_pending,
                "by_status": by_status,
            },
        }, 200