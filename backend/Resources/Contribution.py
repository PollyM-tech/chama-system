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
    Contribution,
    AuditLog,
    AuditAction,
    MembershipRole,
    MembershipStatus,
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
        return None, ({"message": "Only admin or treasurer can perform this financial action."}, 403)

    return (chama, membership), None


def parse_amount(value):
    try:
        amount = Decimal(str(value))
        if amount <= 0:
            return None
        return amount.quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError, ValueError):
        return None


def parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def audit_log(
    action,
    actor_user_id=None,
    target_user_id=None,
    chama_id=None,
    contribution_id=None,
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
            contribution_id=contribution_id,
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


def contribution_dict(contribution):
    return {
        "id": contribution.id,
        "chama_id": contribution.chama_id,
        "user_id": contribution.user_id,
        "member_name": contribution.user.full_name if contribution.user else None,
        "member_username": contribution.user.username if contribution.user else None,
        "amount": float(contribution.amount) if contribution.amount is not None else None,
        "contribution_date": contribution.contribution_date.isoformat() if contribution.contribution_date else None,
        "payment_method": contribution.payment_method,
        "reference_code": contribution.reference_code,
        "notes": contribution.notes,
        "recorded_by_user_id": contribution.recorded_by_user_id,
        "recorded_by_name": contribution.recorded_by.full_name if contribution.recorded_by else None,
        "created_at": contribution.created_at.isoformat() if contribution.created_at else None,
        "updated_at": contribution.updated_at.isoformat() if contribution.updated_at else None,
    }


def member_summary_row(user, contributions):
    total = sum(float(c.amount or 0) for c in contributions)
    latest = max(
        [c.contribution_date for c in contributions if c.contribution_date],
        default=None,
    )

    return {
        "user_id": user.id,
        "full_name": user.full_name,
        "username": user.username,
        "email": user.email,
        "phone_number": user.phone_number,
        "contribution_count": len(contributions),
        "total_contributed": round(total, 2),
        "last_contribution_at": latest.isoformat() if latest else None,
    }


# =========================================================
# RESOURCES
# =========================================================

class ContributionListCreateResource(Resource):
    """
    POST /chamas/<int:chama_id>/contributions
    GET  /chamas/<int:chama_id>/contributions
    """

    @jwt_required()
    def post(self, chama_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        data = request.get_json() or {}

        user_id = data.get("user_id")
        amount = parse_amount(data.get("amount"))
        payment_method = (data.get("payment_method") or "").strip() or None
        reference_code = (data.get("reference_code") or "").strip() or None
        notes = data.get("notes")
        contribution_date_raw = data.get("contribution_date")

        if not user_id:
            return {"message": "user_id is required."}, 400

        if amount is None:
            return {"message": "A valid positive amount is required."}, 400

        target_user = User.query.get(user_id)
        if not target_user:
            return {"message": "Target user not found."}, 404

        target_membership = Membership.query.filter_by(
            user_id=target_user.id,
            chama_id=chama.id,
            status=MembershipStatus.ACTIVE,
        ).first()

        if not target_membership:
            return {"message": "Target user is not an active member of this chama."}, 400

        contribution_date = datetime.utcnow()
        if contribution_date_raw:
            parsed_date = parse_iso_datetime(contribution_date_raw)
            if not parsed_date:
                return {"message": "Invalid contribution_date. Use ISO format."}, 400
            contribution_date = parsed_date

        try:
            contribution = Contribution(
                chama_id=chama.id,
                user_id=target_user.id,
                amount=amount,
                contribution_date=contribution_date,
                recorded_by_user_id=current_user.id,
                payment_method=payment_method,
                reference_code=reference_code,
                notes=notes,
            )

            db.session.add(contribution)
            db.session.commit()

            audit_log(
                action=AuditAction.CONTRIBUTION_RECORDED,
                actor_user_id=current_user.id,
                target_user_id=target_user.id,
                chama_id=chama.id,
                contribution_id=contribution.id,
                membership_id=actor_membership.id,
                description="Contribution recorded for member.",
                new_values=contribution_dict(contribution),
            )

            return {
                "message": "Contribution recorded successfully.",
                "contribution": contribution_dict(contribution),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error recording contribution: {str(e)}"}, 500

    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        query = (
            Contribution.query
            .filter(Contribution.chama_id == chama.id)
            .order_by(Contribution.contribution_date.desc(), Contribution.id.desc())
        )

        user_id = request.args.get("user_id", type=int)
        payment_method = request.args.get("payment_method", type=str)
        start_date = request.args.get("start_date", type=str)
        end_date = request.args.get("end_date", type=str)

        if user_id:
            target_membership = Membership.query.filter_by(
                user_id=user_id,
                chama_id=chama.id,
            ).first()
            if not target_membership:
                return {"message": "The requested user does not belong to this chama."}, 400
            query = query.filter(Contribution.user_id == user_id)

        if payment_method:
            query = query.filter(
                Contribution.payment_method.ilike(f"%{payment_method.strip()}%")
            )

        if start_date:
            start_dt = parse_iso_datetime(start_date)
            if not start_dt:
                return {"message": "Invalid start_date. Use ISO format."}, 400
            query = query.filter(Contribution.contribution_date >= start_dt)

        if end_date:
            end_dt = parse_iso_datetime(end_date)
            if not end_dt:
                return {"message": "Invalid end_date. Use ISO format."}, 400
            query = query.filter(Contribution.contribution_date <= end_dt)

        contributions = query.all()
        total_amount = round(sum(float(c.amount or 0) for c in contributions), 2)

        return {
            "message": "Contributions retrieved successfully.",
            "count": len(contributions),
            "total_amount": total_amount,
            "contributions": [contribution_dict(c) for c in contributions],
        }, 200


class ContributionDetailResource(Resource):
    """
    PATCH  /chamas/<int:chama_id>/contributions/<int:contribution_id>
    DELETE /chamas/<int:chama_id>/contributions/<int:contribution_id>
    """

    @jwt_required()
    def patch(self, chama_id, contribution_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result

        contribution = Contribution.query.filter_by(
            id=contribution_id,
            chama_id=chama.id,
        ).first()

        if not contribution:
            return {"message": "Contribution not found."}, 404

        data = request.get_json() or {}
        old_values = contribution_dict(contribution)

        if "amount" in data:
            amount = parse_amount(data.get("amount"))
            if amount is None:
                return {"message": "A valid positive amount is required."}, 400
            contribution.amount = amount

        if "payment_method" in data:
            payment_method = (data.get("payment_method") or "").strip()
            contribution.payment_method = payment_method or None

        if "reference_code" in data:
            reference_code = (data.get("reference_code") or "").strip()
            contribution.reference_code = reference_code or None

        if "notes" in data:
            contribution.notes = data.get("notes")

        if "contribution_date" in data:
            raw_date = data.get("contribution_date")
            if not raw_date:
                return {"message": "contribution_date cannot be empty."}, 400
            parsed_date = parse_iso_datetime(raw_date)
            if not parsed_date:
                return {"message": "Invalid contribution_date. Use ISO format."}, 400
            contribution.contribution_date = parsed_date

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.CONTRIBUTION_UPDATED,
                actor_user_id=current_user.id,
                target_user_id=contribution.user_id,
                chama_id=chama.id,
                contribution_id=contribution.id,
                membership_id=actor_membership.id,
                description="Contribution record updated.",
                old_values=old_values,
                new_values=contribution_dict(contribution),
            )

            return {
                "message": "Contribution updated successfully.",
                "contribution": contribution_dict(contribution),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error updating contribution: {str(e)}"}, 500

    @jwt_required()
    def delete(self, chama_id, contribution_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result

        contribution = Contribution.query.filter_by(
            id=contribution_id,
            chama_id=chama.id,
        ).first()

        if not contribution:
            return {"message": "Contribution not found."}, 404

        old_values = contribution_dict(contribution)
        target_user_id = contribution.user_id

        try:
            db.session.delete(contribution)
            db.session.commit()

            audit_log(
                action=AuditAction.CONTRIBUTION_DELETED,
                actor_user_id=current_user.id,
                target_user_id=target_user_id,
                chama_id=chama.id,
                contribution_id=contribution_id,
                membership_id=actor_membership.id,
                description="Contribution record deleted.",
                old_values=old_values,
                new_values=None,
                metadata_json={"deleted_contribution_id": contribution_id},
            )

            return {"message": "Contribution deleted successfully."}, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error deleting contribution: {str(e)}"}, 500


class MyContributionHistoryResource(Resource):
    """
    GET /chamas/<int:chama_id>/my-contributions
    """

    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        contributions = (
            Contribution.query
            .filter_by(chama_id=chama.id, user_id=current_user.id)
            .order_by(Contribution.contribution_date.desc(), Contribution.id.desc())
            .all()
        )

        total_amount = round(sum(float(c.amount or 0) for c in contributions), 2)

        return {
            "message": "My contributions retrieved successfully.",
            "member": {
                "user_id": current_user.id,
                "full_name": current_user.full_name,
                "role": membership.role.value if membership.role else None,
            },
            "count": len(contributions),
            "total_amount": total_amount,
            "contributions": [contribution_dict(c) for c in contributions],
        }, 200


class MemberContributionHistoryResource(Resource):
    """
    GET /chamas/<int:chama_id>/members/<int:user_id>/contributions
    """

    @jwt_required()
    def get(self, chama_id, user_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        target_user = User.query.get(user_id)
        if not target_user:
            return {"message": "Target user not found."}, 404

        target_membership = Membership.query.filter_by(
            user_id=target_user.id,
            chama_id=chama.id,
        ).first()

        if not target_membership:
            return {"message": "Target user does not belong to this chama."}, 404

        contributions = (
            Contribution.query
            .filter_by(chama_id=chama.id, user_id=target_user.id)
            .order_by(Contribution.contribution_date.desc(), Contribution.id.desc())
            .all()
        )

        total_amount = round(sum(float(c.amount or 0) for c in contributions), 2)

        return {
            "message": "Member contributions retrieved successfully.",
            "member": {
                "user_id": target_user.id,
                "full_name": target_user.full_name,
                "username": target_user.username,
                "membership_role": target_membership.role.value if target_membership.role else None,
                "membership_status": target_membership.status.value if target_membership.status else None,
            },
            "count": len(contributions),
            "total_amount": total_amount,
            "contributions": [contribution_dict(c) for c in contributions],
        }, 200


class ContributionSummaryResource(Resource):
    """
    GET /chamas/<int:chama_id>/contributions/summary
    """

    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        contributions = (
            Contribution.query
            .filter_by(chama_id=chama.id)
            .order_by(Contribution.contribution_date.desc(), Contribution.id.desc())
            .all()
        )

        total_amount = round(sum(float(c.amount or 0) for c in contributions), 2)

        grouped = {}
        for contribution in contributions:
            grouped.setdefault(contribution.user_id, []).append(contribution)

        member_summaries = []
        for _, user_contributions in grouped.items():
            user = user_contributions[0].user
            if user:
                member_summaries.append(member_summary_row(user, user_contributions))

        member_summaries.sort(
            key=lambda row: (row["total_contributed"], row["contribution_count"]),
            reverse=True,
        )

        return {
            "message": "Contribution summary retrieved successfully.",
            "chama_id": chama.id,
            "chama_name": chama.name,
            "total_contributions_count": len(contributions),
            "total_amount_contributed": total_amount,
            "member_count_with_contributions": len(member_summaries),
            "member_summaries": member_summaries,
        }, 200