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
    Expense,
    AuditLog,
    AuditAction,
    MembershipRole,
    MembershipStatus,
    ExpenseCategory,
    ExpenseStatus,
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
        return None, ({"message": "Access denied. You are not an active member of this chama."}, 403)

    return (chama, membership), None


def require_finance_roles(current_user, chama_id):
    result, error = require_chama_membership(current_user, chama_id)
    if error:
        return None, error

    chama, membership = result
    if membership.role not in {MembershipRole.ADMIN, MembershipRole.TREASURER}:
        return None, ({"message": "Only admin or treasurer can perform this expense action."}, 403)

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


def normalize_expense_category(value):
    if not value:
        return None
    value = value.strip().lower()
    for item in ExpenseCategory:
        if item.value == value:
            return item
    return None


def normalize_expense_status(value):
    if not value:
        return None
    value = value.strip().lower()
    for item in ExpenseStatus:
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


def expense_dict(expense):
    return {
        "id": expense.id,
        "chama_id": expense.chama_id,
        "title": expense.title,
        "description": expense.description,
        "amount": float(expense.amount) if expense.amount is not None else None,
        "category": expense.category.value if expense.category else None,
        "status": expense.status.value if expense.status else None,
        "expense_date": expense.expense_date.isoformat() if expense.expense_date else None,
        "payment_method": expense.payment_method,
        "reference_code": expense.reference_code,
        "notes": expense.notes,
        "recorded_by_user_id": expense.recorded_by_user_id,
        "recorded_by_name": expense.recorded_by.full_name if expense.recorded_by else None,
        "approved_by_user_id": expense.approved_by_user_id,
        "approved_by_name": expense.approved_by.full_name if expense.approved_by else None,
        "created_at": expense.created_at.isoformat() if expense.created_at else None,
        "updated_at": expense.updated_at.isoformat() if expense.updated_at else None,
    }


# =========================================================
# RESOURCES
# =========================================================

class ChamaExpensesResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        query = Expense.query.filter_by(chama_id=chama.id)

        category = request.args.get("category", type=str)
        status = request.args.get("status", type=str)

        if category:
            normalized_category = normalize_expense_category(category)
            if not normalized_category:
                return {"message": "Invalid expense category."}, 400
            query = query.filter(Expense.category == normalized_category)

        if status:
            normalized_status = normalize_expense_status(status)
            if not normalized_status:
                return {"message": "Invalid expense status."}, 400
            query = query.filter(Expense.status == normalized_status)

        expenses = query.order_by(Expense.expense_date.desc(), Expense.id.desc()).all()

        return {
            "message": "Expenses retrieved successfully.",
            "count": len(expenses),
            "expenses": [expense_dict(e) for e in expenses],
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
        amount, amount_error = parse_required_positive_amount(data.get("amount"), "amount")
        category = normalize_expense_category(data.get("category") or "other")
        expense_date, expense_date_error = parse_optional_date(data.get("expense_date"), "expense_date")
        payment_method = (data.get("payment_method") or "").strip() or None
        reference_code = (data.get("reference_code") or "").strip() or None
        notes = data.get("notes")

        if not title:
            return {"message": "title is required."}, 400
        if amount_error:
            return amount_error, 400
        if not category:
            return {"message": "Invalid expense category."}, 400
        if expense_date_error:
            return expense_date_error, 400

        try:
            expense = Expense(
                chama_id=chama.id,
                title=title,
                description=description,
                amount=amount,
                category=category,
                status=ExpenseStatus.RECORDED,
                expense_date=expense_date or datetime.utcnow(),
                payment_method=payment_method,
                reference_code=reference_code,
                notes=notes,
                recorded_by_user_id=current_user.id,
            )

            db.session.add(expense)
            db.session.flush()

            create_notification(
                user_id=current_user.id,
                chama_id=chama.id,
                title="Expense created",
                message=f"Expense '{expense.title}' has been recorded in {chama.name}.",
                notification_type=NotificationType.EXPENSE,
                action_url=f"/chamas/{chama.id}/expenses/{expense.id}",
                metadata_json={"expense_id": expense.id, "status": ExpenseStatus.RECORDED.value},
            )

            db.session.commit()

            audit_log(
                action=AuditAction.EXPENSE_CREATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Expense created.",
                new_values=expense_dict(expense),
            )

            return {
                "message": "Expense created successfully.",
                "expense": expense_dict(expense),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating expense: {str(e)}"}, 500


class ExpenseDetailResource(Resource):
    @jwt_required()
    def get(self, chama_id, expense_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        expense = Expense.query.filter_by(id=expense_id, chama_id=chama.id).first()

        if not expense:
            return {"message": "Expense not found."}, 404

        return {
            "message": "Expense retrieved successfully.",
            "expense": expense_dict(expense),
        }, 200

    @jwt_required()
    def patch(self, chama_id, expense_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        expense = Expense.query.filter_by(id=expense_id, chama_id=chama.id).first()

        if not expense:
            return {"message": "Expense not found."}, 404

        if expense.status != ExpenseStatus.RECORDED:
            return {"message": "Only recorded expenses can be updated."}, 400

        old_values = expense_dict(expense)
        data = request.get_json() or {}

        if "title" in data:
            title = (data.get("title") or "").strip()
            if not title:
                return {"message": "title cannot be empty."}, 400
            expense.title = title

        if "description" in data:
            expense.description = data.get("description")

        if "amount" in data:
            amount, amount_error = parse_required_positive_amount(data.get("amount"), "amount")
            if amount_error:
                return amount_error, 400
            expense.amount = amount

        if "category" in data:
            category = normalize_expense_category(data.get("category"))
            if not category:
                return {"message": "Invalid expense category."}, 400
            expense.category = category

        if "expense_date" in data:
            expense_date, expense_date_error = parse_optional_date(data.get("expense_date"), "expense_date")
            if expense_date_error:
                return expense_date_error, 400
            expense.expense_date = expense_date or expense.expense_date

        if "payment_method" in data:
            expense.payment_method = (data.get("payment_method") or "").strip() or None

        if "reference_code" in data:
            expense.reference_code = (data.get("reference_code") or "").strip() or None

        if "notes" in data:
            expense.notes = data.get("notes")

        try:
            create_notification(
                user_id=expense.recorded_by_user_id,
                chama_id=chama.id,
                title="Expense updated",
                message=f"Expense '{expense.title}' has been updated in {chama.name}.",
                notification_type=NotificationType.EXPENSE,
                action_url=f"/chamas/{chama.id}/expenses/{expense.id}",
                metadata_json={"expense_id": expense.id, "status": expense.status.value},
            )

            db.session.commit()

            audit_log(
                action=AuditAction.EXPENSE_UPDATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Expense updated.",
                old_values=old_values,
                new_values=expense_dict(expense),
            )

            return {
                "message": "Expense updated successfully.",
                "expense": expense_dict(expense),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error updating expense: {str(e)}"}, 500

    @jwt_required()
    def delete(self, chama_id, expense_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        expense = Expense.query.filter_by(id=expense_id, chama_id=chama.id).first()

        if not expense:
            return {"message": "Expense not found."}, 404

        if expense.status not in {ExpenseStatus.RECORDED, ExpenseStatus.CANCELLED}:
            return {"message": "Only recorded or cancelled expenses can be deleted."}, 400

        old_values = expense_dict(expense)

        try:
            create_notification(
                user_id=expense.recorded_by_user_id,
                chama_id=chama.id,
                title="Expense deleted",
                message=f"Expense '{expense.title}' was deleted from {chama.name}.",
                notification_type=NotificationType.EXPENSE,
                action_url=f"/chamas/{chama.id}/expenses",
                metadata_json={"expense_id": expense.id, "status": "deleted"},
            )

            db.session.delete(expense)
            db.session.commit()

            audit_log(
                action=AuditAction.EXPENSE_DELETED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Expense deleted.",
                old_values=old_values,
                new_values=None,
            )

            return {"message": "Expense deleted successfully."}, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error deleting expense: {str(e)}"}, 500


class ExpenseApproveResource(Resource):
    @jwt_required()
    def patch(self, chama_id, expense_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        expense = Expense.query.filter_by(id=expense_id, chama_id=chama.id).first()

        if not expense:
            return {"message": "Expense not found."}, 404

        if expense.status != ExpenseStatus.RECORDED:
            return {"message": "Only recorded expenses can be approved."}, 400

        old_values = expense_dict(expense)
        expense.status = ExpenseStatus.APPROVED
        expense.approved_by_user_id = current_user.id

        try:
            create_notification(
                user_id=expense.recorded_by_user_id,
                chama_id=chama.id,
                title="Expense approved",
                message=f"Expense '{expense.title}' has been approved in {chama.name}.",
                notification_type=NotificationType.EXPENSE,
                action_url=f"/chamas/{chama.id}/expenses/{expense.id}",
                metadata_json={"expense_id": expense.id, "status": ExpenseStatus.APPROVED.value},
            )

            db.session.commit()

            audit_log(
                action=AuditAction.EXPENSE_APPROVED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Expense approved.",
                old_values=old_values,
                new_values=expense_dict(expense),
            )

            return {
                "message": "Expense approved successfully.",
                "expense": expense_dict(expense),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error approving expense: {str(e)}"}, 500


class ExpenseCancelResource(Resource):
    @jwt_required()
    def patch(self, chama_id, expense_id):
        current_user = get_current_user()
        result, error = require_finance_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        expense = Expense.query.filter_by(id=expense_id, chama_id=chama.id).first()

        if not expense:
            return {"message": "Expense not found."}, 404

        if expense.status != ExpenseStatus.RECORDED:
            return {"message": "Only recorded expenses can be cancelled."}, 400

        old_values = expense_dict(expense)
        expense.status = ExpenseStatus.CANCELLED
        expense.approved_by_user_id = None

        try:
            create_notification(
                user_id=expense.recorded_by_user_id,
                chama_id=chama.id,
                title="Expense cancelled",
                message=f"Expense '{expense.title}' has been cancelled in {chama.name}.",
                notification_type=NotificationType.EXPENSE,
                action_url=f"/chamas/{chama.id}/expenses/{expense.id}",
                metadata_json={"expense_id": expense.id, "status": ExpenseStatus.CANCELLED.value},
            )

            db.session.commit()

            audit_log(
                action=AuditAction.EXPENSE_CANCELLED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="Expense cancelled.",
                old_values=old_values,
                new_values=expense_dict(expense),
            )

            return {
                "message": "Expense cancelled successfully.",
                "expense": expense_dict(expense),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error cancelling expense: {str(e)}"}, 500


class ExpenseSummaryResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        expenses = Expense.query.filter_by(chama_id=chama.id).all()

        total_amount = round(sum(float(e.amount or 0) for e in expenses), 2)
        approved_amount = round(
            sum(float(e.amount or 0) for e in expenses if e.status == ExpenseStatus.APPROVED),
            2,
        )
        recorded_amount = round(
            sum(float(e.amount or 0) for e in expenses if e.status == ExpenseStatus.RECORDED),
            2,
        )
        cancelled_amount = round(
            sum(float(e.amount or 0) for e in expenses if e.status == ExpenseStatus.CANCELLED),
            2,
        )

        by_status = {}
        for status in ExpenseStatus:
            by_status[status.value] = Expense.query.filter_by(chama_id=chama.id, status=status).count()

        by_category = {}
        for category in ExpenseCategory:
            category_total = round(
                sum(
                    float(e.amount or 0)
                    for e in expenses
                    if e.category == category and e.status != ExpenseStatus.CANCELLED
                ),
                2,
            )
            by_category[category.value] = category_total

        return {
            "message": "Expense summary retrieved successfully.",
            "summary": {
                "chama_id": chama.id,
                "total_expenses": len(expenses),
                "total_amount": total_amount,
                "approved_amount": approved_amount,
                "recorded_amount": recorded_amount,
                "cancelled_amount": cancelled_amount,
                "by_status": by_status,
                "by_category": by_category,
            },
        }, 200