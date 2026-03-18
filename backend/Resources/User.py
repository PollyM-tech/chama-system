from datetime import datetime
from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from sqlalchemy import or_
from models import (
    db,
    User,
    Membership,
    Chama,
    AuditLog,
    AuditAction,
    UserAccountStatus,
    MembershipStatus,
)


# =========================================================
# HELPERS
# =========================================================

def get_current_user():
    identity = get_jwt_identity()
    if not identity:
        return None
    
    try :
        user_id = int(identity)
    except (ValueError, TypeError):
        return None
    return User.query.get(user_id)


def user_basic_dict(user):
    return {
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "full_name": user.full_name,
        "username": user.username,
        "email": user.email,
        "phone_number": user.phone_number,
        "email_verified": user.email_verified,
        "phone_verified": user.phone_verified,
        "status": user.status.value if user.status else None,
        "is_deleted": user.is_deleted,
        "is_deactivated": user.is_deactivated,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def membership_dict(membership):
    return {
        "membership_id": membership.id,
        "chama_id": membership.chama_id,
        "chama_name": membership.chama.name if membership.chama else None,
        "chama_slug": membership.chama.slug if membership.chama else None,
        "role": membership.role.value if membership.role else None,
        "status": membership.status.value if membership.status else None,
        "joined_at": membership.joined_at.isoformat() if membership.joined_at else None,
        "left_at": membership.left_at.isoformat() if membership.left_at else None,
        "created_at": membership.created_at.isoformat() if membership.created_at else None,
    }


def is_platform_admin(user):
    """
    Placeholder for admin backend access.
    For now, replace this with your real platform admin logic.
    Example later:
    - separate PlatformAdmin table
    - or User.is_staff boolean
    """
    return user and user.username in ["admin", "superadmin"]


def audit_log(
    action,
    actor_user_id=None,
    target_user_id=None,
    chama_id=None,
    description=None,
    old_values=None,
    new_values=None,
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
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception:
        # avoid blocking main flow if audit fails
        pass


# =========================================================
# RESOURCES
# =========================================================

class CurrentUserResource(Resource):
    """
    GET /me
    Return currently logged in user profile
    """
    @jwt_required()
    def get(self):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        if current_user.is_deactivated:
            return {"message": "This account has been deactivated."}, 403

        return {
            "message": "Current user retrieved successfully.",
            "user": user_basic_dict(current_user)
        }, 200


class UserProfileUpdateResource(Resource):
    """
    PUT /me
    Update own platform profile
    """
    @jwt_required()
    def put(self):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        if not current_user.is_active_account:
            return {"message": "Inactive accounts cannot be updated."}, 403

        data = request.get_json() or {}

        old_values = user_basic_dict(current_user)

        username = data.get("username")
        email = data.get("email")
        phone_number = data.get("phone_number")
        first_name = data.get("first_name")
        last_name = data.get("last_name")

        if username:
            existing = User.query.filter(
                User.username == username,
                User.id != current_user.id
            ).first()
            if existing:
                return {"message": "Username already in use."}, 400
            current_user.username = username.strip()

        if email:
            existing = User.query.filter(
                User.email == email,
                User.id != current_user.id
            ).first()
            if existing:
                return {"message": "Email already in use."}, 400
            current_user.email = email.strip().lower()

        if phone_number:
            existing = User.query.filter(
                User.phone_number == phone_number,
                User.id != current_user.id
            ).first()
            if existing:
                return {"message": "Phone number already in use."}, 400
            current_user.phone_number = phone_number.strip()

        if first_name is not None:
            current_user.first_name = first_name.strip() if first_name else None

        if last_name is not None:
            current_user.last_name = last_name.strip() if last_name else None

        db.session.commit()

        audit_log(
            action=AuditAction.USER_UPDATED,
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
            description="User updated own profile.",
            old_values=old_values,
            new_values=user_basic_dict(current_user),
        )

        return {
            "message": "Profile updated successfully.",
            "user": user_basic_dict(current_user)
        }, 200


class ChangePasswordResource(Resource):
    """
    PUT /me/change-password
    Change own password
    """
    @jwt_required()
    def put(self):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        if not current_user.is_active_account:
            return {"message": "Inactive accounts cannot change password."}, 403

        data = request.get_json() or {}

        current_password = data.get("current_password")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if not current_password or not new_password or not confirm_password:
            return {
                "message": "current_password, new_password, and confirm_password are required."
            }, 400

        if not current_user.check_password(current_password):
            return {"message": "Current password is incorrect."}, 400

        if new_password != confirm_password:
            return {"message": "New password and confirm password do not match."}, 400

        if len(new_password) < 8:
            return {"message": "Password must be at least 8 characters long."}, 400

        current_user.set_password(new_password)
        db.session.commit()

        audit_log(
            action=AuditAction.USER_UPDATED,
            actor_user_id=current_user.id,
            target_user_id=current_user.id,
            description="User changed password."
        )

        return {"message": "Password changed successfully."}, 200


class MyChamasResource(Resource):
    """
    GET /my-chamas
    Return all ACTIVE chamas for logged-in user
    """
    @jwt_required()
    def get(self):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        if not current_user.is_active_account:
            return {"message": "Inactive account cannot access chamas."}, 403

        memberships = (
            Membership.query
            .join(Chama, Membership.chama_id == Chama.id)
            .filter(
                Membership.user_id == current_user.id,
                Membership.status == MembershipStatus.ACTIVE
            )
            .order_by(Chama.name.asc())
            .all()
        )

        data = []
        for membership in memberships:
            data.append({
                "membership_id": membership.id,
                "role": membership.role.value if membership.role else None,
                "membership_status": membership.status.value if membership.status else None,
                "joined_at": membership.joined_at.isoformat() if membership.joined_at else None,
                "chama": {
                    "id": membership.chama.id,
                    "name": membership.chama.name,
                    "slug": membership.chama.slug,
                    "status": membership.chama.status.value if membership.chama.status else None,
                    "currency": membership.chama.currency,
                    "contribution_frequency": membership.chama.contribution_frequency,
                    "base_contribution_amount": float(membership.chama.base_contribution_amount) if membership.chama.base_contribution_amount is not None else None,
                }
            })

        return {
            "message": "My chamas retrieved successfully.",
            "count": len(data),
            "chamas": data
        }, 200


class UserMembershipsResource(Resource):
    """
    GET /users/<int:user_id>/memberships

    Rules:
    - a user can see their own memberships
    - platform admin can see any user's memberships
    """
    @jwt_required()
    def get(self, user_id):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        target_user = User.query.get(user_id)
        if not target_user:
            return {"message": "Target user not found."}, 404

        if current_user.id != target_user.id and not is_platform_admin(current_user):
            return {"message": "You are not allowed to view this user's memberships."}, 403

        memberships = (
            Membership.query
            .join(Chama, Membership.chama_id == Chama.id)
            .filter(Membership.user_id == target_user.id)
            .order_by(Membership.created_at.desc())
            .all()
        )

        return {
            "message": "User memberships retrieved successfully.",
            "user": user_basic_dict(target_user),
            "count": len(memberships),
            "memberships": [membership_dict(m) for m in memberships]
        }, 200


class UserDetailResource(Resource):
    """
    GET /users/<int:user_id>
    Platform user detail
    """
    @jwt_required()
    def get(self, user_id):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        target_user = User.query.get(user_id)
        if not target_user:
            return {"message": "Target user not found."}, 404

        if current_user.id != target_user.id and not is_platform_admin(current_user):
            return {"message": "You are not allowed to view this user."}, 403

        return {
            "message": "User retrieved successfully.",
            "user": user_basic_dict(target_user)
        }, 200


class UserListResource(Resource):
    """
    GET /users
    Platform admin backend only
    Supports search and status filtering
    """
    @jwt_required()
    def get(self):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        if not is_platform_admin(current_user):
            return {"message": "Only platform admin can view all users."}, 403

        search = request.args.get("search", "").strip()
        status = request.args.get("status", "").strip().lower()

        query = User.query

        if search:
            query = query.filter(
                or_(
                    User.first_name.ilike(f"%{search}%"),
                    User.last_name.ilike(f"%{search}%"),
                    User.username.ilike(f"%{search}%"),
                    User.email.ilike(f"%{search}%"),
                    User.phone_number.ilike(f"%{search}%"),
                )
            )

        if status:
            if status == "active":
                query = query.filter(User.status == UserAccountStatus.ACTIVE)
            elif status == "deleted":
                query = query.filter(User.status == UserAccountStatus.DELETED)
            elif status == "deactivated":
                query = query.filter(User.status == UserAccountStatus.DEACTIVATED)

        users = query.order_by(User.created_at.desc()).all()

        return {
            "message": "Users retrieved successfully.",
            "count": len(users),
            "users": [user_basic_dict(user) for user in users]
        }, 200


class SoftDeleteUserResource(Resource):
    """
    DELETE /users/<int:user_id>/soft-delete

    Recoverable delete for admin backend
    """
    @jwt_required()
    def delete(self, user_id):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        if not is_platform_admin(current_user):
            return {"message": "Only platform admin can soft delete users."}, 403

        target_user = User.query.get(user_id)
        if not target_user:
            return {"message": "Target user not found."}, 404

        if target_user.is_deactivated:
            return {"message": "Deactivated user cannot be soft deleted."}, 400

        if target_user.is_deleted:
            return {"message": "User is already soft deleted."}, 400

        data = request.get_json(silent=True) or {}
        reason = data.get("reason")

        old_values = user_basic_dict(target_user)

        target_user.soft_delete(by_user_id=current_user.id, reason=reason)
        db.session.commit()

        audit_log(
            action=AuditAction.USER_SOFT_DELETED,
            actor_user_id=current_user.id,
            target_user_id=target_user.id,
            description="Platform admin soft deleted user.",
            old_values=old_values,
            new_values=user_basic_dict(target_user),
        )

        return {
            "message": "User soft deleted successfully.",
            "user": user_basic_dict(target_user)
        }, 200


class RestoreUserResource(Resource):
    """
    PATCH /users/<int:user_id>/restore

    Restore soft deleted user
    """
    @jwt_required()
    def patch(self, user_id):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        if not is_platform_admin(current_user):
            return {"message": "Only platform admin can restore users."}, 403

        target_user = User.query.get(user_id)
        if not target_user:
            return {"message": "Target user not found."}, 404

        if target_user.is_deactivated:
            return {"message": "Deactivated users cannot be restored."}, 400

        if not target_user.is_deleted:
            return {"message": "User is not soft deleted."}, 400

        old_values = user_basic_dict(target_user)

        target_user.restore()
        db.session.commit()

        audit_log(
            action=AuditAction.USER_RESTORED,
            actor_user_id=current_user.id,
            target_user_id=target_user.id,
            description="Platform admin restored user.",
            old_values=old_values,
            new_values=user_basic_dict(target_user),
        )

        return {
            "message": "User restored successfully.",
            "user": user_basic_dict(target_user)
        }, 200


class DeactivateUserResource(Resource):
    """
    PATCH /users/<int:user_id>/deactivate

    Final irreversible shutdown
    """
    @jwt_required()
    def patch(self, user_id):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        if not is_platform_admin(current_user):
            return {"message": "Only platform admin can deactivate users."}, 403

        target_user = User.query.get(user_id)
        if not target_user:
            return {"message": "Target user not found."}, 404

        if target_user.is_deactivated:
            return {"message": "User is already deactivated."}, 400

        data = request.get_json(silent=True) or {}
        reason = data.get("reason")

        old_values = user_basic_dict(target_user)

        target_user.deactivate(by_user_id=current_user.id, reason=reason)
        db.session.commit()

        audit_log(
            action=AuditAction.USER_DEACTIVATED,
            actor_user_id=current_user.id,
            target_user_id=target_user.id,
            description="Platform admin permanently deactivated user.",
            old_values=old_values,
            new_values=user_basic_dict(target_user),
        )

        return {
            "message": "User permanently deactivated successfully.",
            "user": user_basic_dict(target_user)
        }, 200


class SignUpResource(Resource):
    """
    POST /auth/signup
    Create a new user account
    """
    def post(self):
        data = request.get_json() or {}

        # Validate required fields
        username = data.get("username", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        confirm_password = data.get("confirm_password", "")
        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()

        if not username or not email or not password or not confirm_password:
            return {
                "message": "username, email, password, and confirm_password are required."
            }, 400

        if len(username) < 3:
            return {"message": "Username must be at least 3 characters long."}, 400

        if len(password) < 8:
            return {"message": "Password must be at least 8 characters long."}, 400

        if password != confirm_password:
            return {"message": "Password and confirm password do not match."}, 400

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return {"message": "Username already in use."}, 400

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return {"message": "Email already registered."}, 400

        # Create new user
        try:
            user = User(
                username=username,
                email=email,
                first_name=first_name or None,
                last_name=last_name or None
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            audit_log(
                action=AuditAction.USER_CREATED,
                actor_user_id=user.id,
                target_user_id=user.id,
                description="New user registered."
            )

            # Generate JWT tokens
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)

            return {
                "message": "Account created successfully.",
                "user": user_basic_dict(user),
                "access_token": access_token,
                "refresh_token": refresh_token
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating account: {str(e)}"}, 500


class LoginResource(Resource):
    """
    POST /auth/login
    Authenticate user and return JWT tokens
    """
    def post(self):
        data = request.get_json() or {}

        # Accept either username or email
        username_or_email = data.get("username_or_email", "").strip().lower()
        password = data.get("password", "")

        if not username_or_email or not password:
            return {
                "message": "username_or_email and password are required."
            }, 400

        # Find user by username or email
        user = User.query.filter(
            or_(
                User.username == username_or_email,
                User.email == username_or_email
            )
        ).first()

        if not user:
            return {"message": "Invalid credentials."}, 401

        # Check password
        if not user.check_password(password):
            return {"message": "Invalid credentials."}, 401

        # Check account status
        if user.is_deactivated:
            return {"message": "This account has been deactivated."}, 403

        if user.is_deleted:
            return {"message": "This account has been deleted."}, 403

        # Update last login time
        user.last_login_at = datetime.utcnow()
        db.session.commit()

        # Generate JWT tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        audit_log(
            action=AuditAction.USER_UPDATED,
            actor_user_id=user.id,
            target_user_id=user.id,
            description="User logged in."
        )

        return {
            "message": "Login successful.",
            "user": user_basic_dict(user),
            "access_token": access_token,
            "refresh_token": refresh_token
        }, 200


class RefreshTokenResource(Resource):
    """
    POST /auth/refresh
    Refresh access token using refresh token
    """
    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        if not identity:
            return {"message": "Invalid refresh token."}, 401

        user = User.query.get(identity)
        if not user:
            return {"message": "User not found."}, 404

        if user.is_deactivated:
            return {"message": "This account has been deactivated."}, 403

        if user.is_deleted:
            return {"message": "This account has been deleted."}, 403

        # Generate new access token
        access_token = create_access_token(identity=user.id)

        return {
            "message": "Token refreshed successfully.",
            "access_token": access_token
        }, 200
    