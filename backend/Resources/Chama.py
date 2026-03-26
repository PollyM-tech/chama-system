from datetime import datetime

from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import or_

from models import (
    db,
    User,
    Chama,
    Membership,
    ChamaInvite,
    AuditLog,
    AuditAction,
    MembershipRole,
    MembershipStatus,
    ChamaStatus,
    InviteStatus,
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


def audit_log(
    action,
    actor_user_id=None,
    target_user_id=None,
    chama_id=None,
    description=None,
    membership_id=None,
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


def chama_dict(chama, membership=None):
    return {
        "id": chama.id,
        "name": chama.name,
        "slug": chama.slug,
        "description": chama.description,
        "status": chama.status.value if chama.status else None,
        "currency": chama.currency,
        "contribution_frequency": chama.contribution_frequency,
        "base_contribution_amount": float(chama.base_contribution_amount)
        if chama.base_contribution_amount is not None else None,
        "created_by_user_id": chama.created_by_user_id,
        "created_at": chama.created_at.isoformat() if chama.created_at else None,
        "updated_at": chama.updated_at.isoformat() if chama.updated_at else None,
        "my_membership": {
            "membership_id": membership.id,
            "role": membership.role.value if membership.role else None,
            "status": membership.status.value if membership.status else None,
            "joined_at": membership.joined_at.isoformat() if membership.joined_at else None,
        } if membership else None,
    }


def membership_dict(membership):
    return {
        "membership_id": membership.id,
        "user_id": membership.user_id,
        "full_name": membership.user.full_name if membership.user else None,
        "username": membership.user.username if membership.user else None,
        "email": membership.user.email if membership.user else None,
        "phone_number": membership.user.phone_number if membership.user else None,
        "role": membership.role.value if membership.role else None,
        "status": membership.status.value if membership.status else None,
        "joined_at": membership.joined_at.isoformat() if membership.joined_at else None,
        "left_at": membership.left_at.isoformat() if membership.left_at else None,
        "created_at": membership.created_at.isoformat() if membership.created_at else None,
    }


def invite_dict(invite):
    return {
        "id": invite.id,
        "chama_id": invite.chama_id,
        "email": invite.email,
        "phone_number": invite.phone_number,
        "role_to_assign": invite.role_to_assign.value if invite.role_to_assign else None,
        "status": invite.status.value if invite.status else None,
        "invited_user_id": invite.invited_user_id,
        "invited_by_user_id": invite.invited_by_user_id,
        "expires_at": invite.expires_at.isoformat() if invite.expires_at else None,
        "accepted_at": invite.accepted_at.isoformat() if invite.accepted_at else None,
        "revoked_at": invite.revoked_at.isoformat() if invite.revoked_at else None,
        "created_at": invite.created_at.isoformat() if invite.created_at else None,
    }


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


def require_chama_roles(current_user, chama_id, allowed_roles):
    result, error = require_chama_membership(current_user, chama_id)
    if error:
        return None, error

    chama, membership = result

    if membership.role not in allowed_roles:
        return None, ({"message": "You do not have permission to perform this action in this chama."}, 403)

    return (chama, membership), None


def can_manage_onboarding(membership):
    return membership.role in {
        MembershipRole.ADMIN,
        MembershipRole.TREASURER,
        MembershipRole.SECRETARY,
    }


def normalize_role(value):
    if not value:
        return None

    value = value.strip().lower()
    for role in MembershipRole:
        if role.value == value:
            return role

    return None


def normalize_chama_status(value):
    if not value:
        return None

    value = value.strip().lower()
    for status in ChamaStatus:
        if status.value == value:
            return status

    return None


def normalize_membership_status(value):
    if not value:
        return None

    value = value.strip().lower()
    for status in MembershipStatus:
        if status.value == value:
            return status

    return None


# =========================================================
# RESOURCES
# =========================================================

class ChamaCreateResource(Resource):
    @jwt_required()
    def post(self):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        if not current_user.is_active_account:
            return {"message": "Inactive account cannot create a chama."}, 403

        data = request.get_json() or {}

        name = (data.get("name") or "").strip()
        slug = (data.get("slug") or "").strip().lower()
        description = data.get("description")
        currency = (data.get("currency") or "KES").strip().upper()
        contribution_frequency = data.get("contribution_frequency")
        base_contribution_amount = data.get("base_contribution_amount")

        if not name:
            return {"message": "name is required."}, 400

        if not slug:
            return {"message": "slug is required."}, 400

        existing_slug = Chama.query.filter_by(slug=slug).first()
        if existing_slug:
            return {"message": "Slug already exists."}, 400

        try:
            chama = Chama(
                name=name,
                slug=slug,
                description=description,
                currency=currency,
                contribution_frequency=contribution_frequency,
                base_contribution_amount=base_contribution_amount,
                status=ChamaStatus.ACTIVE,
                created_by_user_id=current_user.id,
            )
            db.session.add(chama)
            db.session.flush()

            creator_membership = Membership(
                user_id=current_user.id,
                chama_id=chama.id,
                role=MembershipRole.ADMIN,
                status=MembershipStatus.ACTIVE,
                joined_at=datetime.utcnow(),
                approved_by_user_id=current_user.id,
                invited_by_user_id=current_user.id,
            )
            db.session.add(creator_membership)
            db.session.commit()

            audit_log(
                action=AuditAction.CHAMA_CREATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                description="User created a new chama.",
                new_values=chama_dict(chama, creator_membership),
            )

            audit_log(
                action=AuditAction.MEMBERSHIP_CREATED,
                actor_user_id=current_user.id,
                target_user_id=current_user.id,
                chama_id=chama.id,
                membership_id=creator_membership.id,
                description="Creator added as chama admin.",
                new_values=membership_dict(creator_membership),
            )

            return {
                "message": "Chama created successfully.",
                "chama": chama_dict(chama, creator_membership),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating chama: {str(e)}"}, 500


class ChamaDetailResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        return {
            "message": "Chama retrieved successfully.",
            "chama": chama_dict(chama, membership),
        }, 200


class ChamaUpdateResource(Resource):
    @jwt_required()
    def put(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_roles(
            current_user,
            chama_id,
            {
                MembershipRole.ADMIN,
                MembershipRole.TREASURER,
                MembershipRole.SECRETARY,
            },
        )
        if error:
            return error

        chama, membership = result
        data = request.get_json() or {}

        old_values = chama_dict(chama, membership)

        name = data.get("name")
        slug = data.get("slug")
        description = data.get("description")
        currency = data.get("currency")
        contribution_frequency = data.get("contribution_frequency")
        base_contribution_amount = data.get("base_contribution_amount")
        status = data.get("status")

        if name is not None:
            name = name.strip()
            if not name:
                return {"message": "name cannot be empty."}, 400
            chama.name = name

        if slug is not None:
            slug = slug.strip().lower()
            if not slug:
                return {"message": "slug cannot be empty."}, 400

            existing_slug = Chama.query.filter(
                Chama.slug == slug,
                Chama.id != chama.id,
            ).first()
            if existing_slug:
                return {"message": "Slug already exists."}, 400

            chama.slug = slug

        if description is not None:
            chama.description = description

        if currency is not None:
            currency = currency.strip().upper()
            if not currency:
                return {"message": "currency cannot be empty."}, 400
            chama.currency = currency

        if contribution_frequency is not None:
            chama.contribution_frequency = contribution_frequency

        if base_contribution_amount is not None:
            chama.base_contribution_amount = base_contribution_amount

        if status is not None:
            normalized_status = normalize_chama_status(status)
            if not normalized_status:
                return {"message": "Invalid chama status."}, 400
            chama.status = normalized_status

        db.session.commit()

        audit_log(
            action=AuditAction.CHAMA_UPDATED,
            actor_user_id=current_user.id,
            chama_id=chama.id,
            membership_id=membership.id,
            description="Chama settings updated.",
            old_values=old_values,
            new_values=chama_dict(chama, membership),
        )

        return {
            "message": "Chama updated successfully.",
            "chama": chama_dict(chama, membership),
        }, 200


class ChamaMembersResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        status_filter = (request.args.get("status") or "").strip().lower()

        query = (
            Membership.query
            .join(User, Membership.user_id == User.id)
            .filter(Membership.chama_id == chama.id)
            .order_by(Membership.created_at.desc())
        )

        if status_filter:
            normalized_status = normalize_membership_status(status_filter)
            if not normalized_status:
                return {"message": "Invalid membership status filter."}, 400
            query = query.filter(Membership.status == normalized_status)

        memberships = query.all()

        return {
            "message": "Chama members retrieved successfully.",
            "chama": chama_dict(chama, membership),
            "count": len(memberships),
            "members": [membership_dict(m) for m in memberships],
        }, 200


class ChamaInviteMemberResource(Resource):
    @jwt_required()
    def post(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result

        if not can_manage_onboarding(actor_membership):
            return {"message": "Only admin, treasurer, or secretary can invite members."}, 403

        data = request.get_json() or {}

        email = (data.get("email") or "").strip().lower()
        phone_number = (data.get("phone_number") or "").strip()
        role_value = (data.get("role") or "member").strip().lower()
        expires_in_days = data.get("expires_in_days", 7)

        if not email and not phone_number:
            return {"message": "At least one of email or phone_number is required."}, 400

        role_to_assign = normalize_role(role_value)
        if not role_to_assign:
            return {"message": "Invalid membership role."}, 400

        existing_user = None
        filters = []

        if email:
            filters.append(User.email == email)

        if phone_number:
            filters.append(User.phone_number == phone_number)

        if filters:
            existing_user = User.query.filter(or_(*filters)).first()

        if existing_user:
            existing_membership = Membership.query.filter_by(
                user_id=existing_user.id,
                chama_id=chama.id,
            ).first()

            if existing_membership and existing_membership.status in {
                MembershipStatus.ACTIVE,
                MembershipStatus.PENDING,
                MembershipStatus.INVITED,
                MembershipStatus.SUSPENDED,
            }:
                return {"message": "This user already has a membership record in this chama."}, 400

        invite_query = ChamaInvite.query.filter(
            ChamaInvite.chama_id == chama.id,
            ChamaInvite.status == InviteStatus.PENDING,
        )

        contact_filters = []
        if email:
            contact_filters.append(ChamaInvite.email == email)
        if phone_number:
            contact_filters.append(ChamaInvite.phone_number == phone_number)

        if contact_filters:
            existing_pending_invite = invite_query.filter(or_(*contact_filters)).first()
            if existing_pending_invite:
                return {"message": "A pending invite already exists for this contact."}, 400

        try:
            invite = ChamaInvite(
                chama_id=chama.id,
                invited_user_id=existing_user.id if existing_user else None,
                email=email or None,
                phone_number=phone_number or None,
                role_to_assign=role_to_assign,
                status=InviteStatus.PENDING,
                token=ChamaInvite.generate_token(),
                expires_at=ChamaInvite.default_expiry(days=expires_in_days),
                invited_by_user_id=current_user.id,
            )

            db.session.add(invite)
            db.session.commit()

            audit_log(
                action=AuditAction.INVITE_CREATED,
                actor_user_id=current_user.id,
                target_user_id=existing_user.id if existing_user else None,
                chama_id=chama.id,
                membership_id=actor_membership.id,
                description="Chama invite created.",
                new_values=invite_dict(invite),
            )

            return {
                "message": "Invite created successfully.",
                "invite": invite_dict(invite),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating invite: {str(e)}"}, 500


class ChamaPendingInvitesResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result

        if not can_manage_onboarding(actor_membership):
            return {"message": "You are not allowed to view chama invites."}, 403

        invites = (
            ChamaInvite.query
            .filter_by(chama_id=chama.id)
            .order_by(ChamaInvite.created_at.desc())
            .all()
        )

        return {
            "message": "Chama invites retrieved successfully.",
            "count": len(invites),
            "invites": [invite_dict(invite) for invite in invites],
        }, 200


class ChamaRevokeInviteResource(Resource):
    @jwt_required()
    def patch(self, chama_id, invite_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result

        if not can_manage_onboarding(actor_membership):
            return {"message": "You are not allowed to revoke invites."}, 403

        invite = ChamaInvite.query.filter_by(id=invite_id, chama_id=chama.id).first()
        if not invite:
            return {"message": "Invite not found."}, 404

        if invite.status != InviteStatus.PENDING:
            return {"message": "Only pending invites can be revoked."}, 400

        old_values = invite_dict(invite)
        invite.revoke()
        db.session.commit()

        audit_log(
            action=AuditAction.INVITE_REVOKED,
            actor_user_id=current_user.id,
            target_user_id=invite.invited_user_id,
            chama_id=chama.id,
            membership_id=actor_membership.id,
            description="Chama invite revoked.",
            old_values=old_values,
            new_values=invite_dict(invite),
        )

        return {
            "message": "Invite revoked successfully.",
            "invite": invite_dict(invite),
        }, 200


class ChamaAddExistingMemberResource(Resource):
    @jwt_required()
    def post(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result

        if not can_manage_onboarding(actor_membership):
            return {"message": "Only admin, treasurer, or secretary can onboard members."}, 403

        data = request.get_json() or {}
        user_id = data.get("user_id")
        role_value = (data.get("role") or "member").strip().lower()

        if not user_id:
            return {"message": "user_id is required."}, 400

        target_user = User.query.get(user_id)
        if not target_user:
            return {"message": "Target user not found."}, 404

        if not target_user.is_active_account:
            return {"message": "Inactive user cannot be added to a chama."}, 400

        role = normalize_role(role_value)
        if not role:
            return {"message": "Invalid membership role."}, 400

        existing_membership = Membership.query.filter_by(
            user_id=target_user.id,
            chama_id=chama.id,
        ).first()

        if existing_membership:
            return {"message": "This user already has a membership record in this chama."}, 400

        try:
            membership = Membership(
                user_id=target_user.id,
                chama_id=chama.id,
                role=role,
                status=MembershipStatus.ACTIVE,
                joined_at=datetime.utcnow(),
                invited_by_user_id=current_user.id,
                approved_by_user_id=current_user.id,
            )

            db.session.add(membership)
            db.session.commit()

            audit_log(
                action=AuditAction.MEMBERSHIP_CREATED,
                actor_user_id=current_user.id,
                target_user_id=target_user.id,
                chama_id=chama.id,
                membership_id=membership.id,
                description="Existing platform user added to chama.",
                new_values=membership_dict(membership),
            )

            return {
                "message": "Member added successfully.",
                "membership": membership_dict(membership),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error adding member: {str(e)}"}, 500


class ChamaMembershipRoleUpdateResource(Resource):
    @jwt_required()
    def patch(self, chama_id, membership_id):
        current_user = get_current_user()
        result, error = require_chama_roles(
            current_user,
            chama_id,
            {MembershipRole.ADMIN},
        )
        if error:
            return error

        chama, actor_membership = result

        membership = Membership.query.filter_by(
            id=membership_id,
            chama_id=chama.id,
        ).first()
        if not membership:
            return {"message": "Membership not found."}, 404

        data = request.get_json() or {}
        new_role_value = (data.get("role") or "").strip().lower()
        new_role = normalize_role(new_role_value)

        if not new_role:
            return {"message": "Invalid membership role."}, 400

        old_values = membership_dict(membership)
        membership.role = new_role
        db.session.commit()

        audit_log(
            action=AuditAction.MEMBERSHIP_UPDATED,
            actor_user_id=current_user.id,
            target_user_id=membership.user_id,
            chama_id=chama.id,
            membership_id=membership.id,
            description="Membership role updated.",
            old_values=old_values,
            new_values=membership_dict(membership),
        )

        return {
            "message": "Membership role updated successfully.",
            "membership": membership_dict(membership),
        }, 200


class ChamaSuspendMembershipResource(Resource):
    @jwt_required()
    def patch(self, chama_id, membership_id):
        current_user = get_current_user()
        result, error = require_chama_roles(
            current_user,
            chama_id,
            {
                MembershipRole.ADMIN,
                MembershipRole.TREASURER,
                MembershipRole.SECRETARY,
            },
        )
        if error:
            return error

        chama, actor_membership = result

        membership = Membership.query.filter_by(
            id=membership_id,
            chama_id=chama.id,
        ).first()
        if not membership:
            return {"message": "Membership not found."}, 404

        if membership.status != MembershipStatus.ACTIVE:
            return {"message": "Only active memberships can be suspended."}, 400

        if membership.user_id == current_user.id and membership.role == MembershipRole.ADMIN:
            return {"message": "You cannot suspend your own admin membership."}, 400

        old_values = membership_dict(membership)
        membership.suspend()
        db.session.commit()

        audit_log(
            action=AuditAction.MEMBERSHIP_SUSPENDED,
            actor_user_id=current_user.id,
            target_user_id=membership.user_id,
            chama_id=chama.id,
            membership_id=membership.id,
            description="Membership suspended.",
            old_values=old_values,
            new_values=membership_dict(membership),
        )

        return {
            "message": "Membership suspended successfully.",
            "membership": membership_dict(membership),
        }, 200


class ChamaRestoreMembershipResource(Resource):
    @jwt_required()
    def patch(self, chama_id, membership_id):
        current_user = get_current_user()
        result, error = require_chama_roles(
            current_user,
            chama_id,
            {
                MembershipRole.ADMIN,
                MembershipRole.TREASURER,
                MembershipRole.SECRETARY,
            },
        )
        if error:
            return error

        chama, actor_membership = result

        membership = Membership.query.filter_by(
            id=membership_id,
            chama_id=chama.id,
        ).first()
        if not membership:
            return {"message": "Membership not found."}, 404

        if membership.status != MembershipStatus.SUSPENDED:
            return {"message": "Only suspended memberships can be restored."}, 400

        old_values = membership_dict(membership)
        membership.status = MembershipStatus.ACTIVE
        membership.left_at = None
        membership.joined_at = membership.joined_at or datetime.utcnow()

        db.session.commit()

        audit_log(
            action=AuditAction.MEMBERSHIP_RESTORED,
            actor_user_id=current_user.id,
            target_user_id=membership.user_id,
            chama_id=chama.id,
            membership_id=membership.id,
            description="Membership restored to active.",
            old_values=old_values,
            new_values=membership_dict(membership),
        )

        return {
            "message": "Membership restored successfully.",
            "membership": membership_dict(membership),
        }, 200

class ChamaRemoveMembershipResource(Resource):
    @jwt_required()
    def patch(self, chama_id, membership_id):
        current_user = get_current_user()
        result, error = require_chama_roles(
            current_user,
            chama_id,
            {
                MembershipRole.ADMIN,
                MembershipRole.TREASURER,
                MembershipRole.SECRETARY,
            },
        )
        if error:
            return error

        chama, actor_membership = result

        membership = Membership.query.filter_by(
            id=membership_id,
            chama_id=chama.id,
        ).first()
        if not membership:
            return {"message": "Membership not found."}, 404

        if membership.status in {MembershipStatus.LEFT, MembershipStatus.REMOVED}:
            return {"message": "Membership is already inactive."}, 400

        if membership.user_id == current_user.id and membership.role == MembershipRole.ADMIN:
            return {"message": "You cannot remove your own admin membership."}, 400

        old_values = membership_dict(membership)
        membership.remove()
        db.session.commit()

        audit_log(
            action=AuditAction.MEMBERSHIP_REMOVED,
            actor_user_id=current_user.id,
            target_user_id=membership.user_id,
            chama_id=chama.id,
            membership_id=membership.id,
            description="Membership removed from chama.",
            old_values=old_values,
            new_values=membership_dict(membership),
        )

        return {
            "message": "Membership removed successfully.",
            "membership": membership_dict(membership),
        }, 200