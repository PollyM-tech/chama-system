from datetime import datetime, timedelta
import enum
import secrets

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint, Index
from werkzeug.security import generate_password_hash, check_password_hash


db = SQLAlchemy()


# =========================================================
# ENUMS
# =========================================================

class UserAccountStatus(enum.Enum):
    ACTIVE = "active"
    DELETED = "deleted"
    DEACTIVATED = "deactivated"


class MembershipRole(enum.Enum):
    ADMIN = "admin"
    TREASURER = "treasurer"
    SECRETARY = "secretary"
    CHAIRPERSON = "chairperson"
    MEMBER = "member"


class MembershipStatus(enum.Enum):
    ACTIVE = "active"
    INVITED = "invited"
    PENDING = "pending"
    SUSPENDED = "suspended"
    LEFT = "left"
    REMOVED = "removed"


class ChamaStatus(enum.Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    SUSPENDED = "suspended"


class InviteStatus(enum.Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"


class LoanStatus(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    DISBURSED = "disbursed"
    PARTIALLY_REPAID = "partially_repaid"
    REPAID = "repaid"
    DEFAULTED = "defaulted"
    CANCELLED = "cancelled"


class PollStatus(enum.Enum):
    DRAFT = "draft"
    OPEN = "open"
    CLOSED = "closed"
    ARCHIVED = "archived"


class AuditAction(enum.Enum):
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_SOFT_DELETED = "user_soft_deleted"
    USER_RESTORED = "user_restored"
    USER_DEACTIVATED = "user_deactivated"

    CHAMA_CREATED = "chama_created"
    CHAMA_UPDATED = "chama_updated"

    MEMBERSHIP_CREATED = "membership_created"
    MEMBERSHIP_UPDATED = "membership_updated"
    MEMBERSHIP_SUSPENDED = "membership_suspended"
    MEMBERSHIP_REMOVED = "membership_removed"
    MEMBERSHIP_RESTORED = "membership_restored"

    INVITE_CREATED = "invite_created"
    INVITE_ACCEPTED = "invite_accepted"
    INVITE_REVOKED = "invite_revoked"

    CONTRIBUTION_RECORDED = "contribution_recorded"
    CONTRIBUTION_UPDATED = "contribution_updated"
    CONTRIBUTION_DELETED = "contribution_deleted"

    LOAN_APPLIED = "loan_applied"
    LOAN_APPROVED = "loan_approved"
    LOAN_REJECTED = "loan_rejected"
    LOAN_DISBURSED = "loan_disbursed"
    LOAN_UPDATED = "loan_updated"
    LOAN_DELETED = "loan_deleted"
    LOAN_REPAYMENT_RECORDED = "loan_repayment_recorded"

    POLL_CREATED = "poll_created"
    POLL_UPDATED = "poll_updated"
    POLL_DELETED = "poll_deleted"

    VOTE_CAST = "vote_cast"

    INVESTMENT_CREATED = "investment_created"
    INVESTMENT_UPDATED = "investment_updated"
    INVESTMENT_APPROVED = "investment_approved"
    INVESTMENT_CLOSED = "investment_closed"
    INVESTMENT_CANCELLED = "investment_cancelled"
    INVESTMENT_RETURN_RECORDED = "investment_return_recorded"
    INVESTMENT_DELETED = "investment_deleted"


class InvestmentStatus(enum.Enum):
    PROPOSED = "proposed"
    ACTIVE = "active"
    CLOSED = "closed"
    CANCELLED = "cancelled"


class InvestmentType(enum.Enum):
    STOCKS = "stocks"
    BONDS = "bonds"
    MONEY_MARKET = "money_market"
    SACCO = "sacco"
    REAL_ESTATE = "real_estate"
    BUSINESS = "business"
    FIXED_DEPOSIT = "fixed_deposit"
    OTHER = "other"


class ReturnType(enum.Enum):
    DIVIDEND = "dividend"
    INTEREST = "interest"
    PROFIT_SHARE = "profit_share"
    CAPITAL_GAIN = "capital_gain"
    OTHER = "other"


class LoanInterestType(enum.Enum):
    FLAT = "flat"
    REDUCING_BALANCE = "reducing_balance"


class RepeatFrequency(enum.Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    YEARLY = "yearly"


# =========================================================
# MIXINS
# =========================================================

class TimestampMixin:
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class UserLifecycleMixin:
    status = db.Column(
        db.Enum(UserAccountStatus),
        default=UserAccountStatus.ACTIVE,
        nullable=False,
        index=True,
    )

    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    delete_reason = db.Column(db.Text, nullable=True)

    is_deactivated = db.Column(db.Boolean, default=False, nullable=False)
    deactivated_at = db.Column(db.DateTime, nullable=True)
    deactivated_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    deactivation_reason = db.Column(db.Text, nullable=True)

    def soft_delete(self, by_user_id=None, reason=None):
        if self.is_deactivated:
            raise ValueError("Deactivated users cannot be soft deleted.")

        self.status = UserAccountStatus.DELETED
        self.is_deleted = True
        self.deleted_at = datetime.utcnow()
        self.deleted_by_user_id = by_user_id
        self.delete_reason = reason

    def restore(self):
        if self.is_deactivated:
            raise ValueError("Deactivated users cannot be restored.")

        self.status = UserAccountStatus.ACTIVE
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by_user_id = None
        self.delete_reason = None

    def deactivate(self, by_user_id=None, reason=None):
        self.status = UserAccountStatus.DEACTIVATED
        self.is_deactivated = True
        self.deactivated_at = datetime.utcnow()
        self.deactivated_by_user_id = by_user_id
        self.deactivation_reason = reason

        self.is_deleted = True
        if not self.deleted_at:
            self.deleted_at = datetime.utcnow()
            self.deleted_by_user_id = by_user_id
            self.delete_reason = self.delete_reason or "Auto-marked deleted during deactivation"

    @property
    def is_active_account(self):
        return (
            self.status == UserAccountStatus.ACTIVE
            and not self.is_deleted
            and not self.is_deactivated
        )


# =========================================================
# CORE MODELS
# =========================================================

class User(db.Model, TimestampMixin, UserLifecycleMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    first_name = db.Column(db.String(80), nullable=True)
    last_name = db.Column(db.String(80), nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone_number = db.Column(db.String(30), unique=True, nullable=True, index=True)

    password_hash = db.Column(db.String(255), nullable=False)

    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    phone_verified = db.Column(db.Boolean, default=False, nullable=False)

    last_login_at = db.Column(db.DateTime, nullable=True)

    memberships = db.relationship(
        "Membership",
        back_populates="user",
        lazy=True,
        cascade="all, delete-orphan",
        foreign_keys="Membership.user_id",
    )

    invites_received = db.relationship(
        "ChamaInvite",
        back_populates="invited_user",
        lazy=True,
        foreign_keys="ChamaInvite.invited_user_id",
    )

    contributions = db.relationship(
        "Contribution",
        back_populates="user",
        lazy=True,
        foreign_keys="Contribution.user_id",
    )

    recorded_contributions = db.relationship(
        "Contribution",
        back_populates="recorded_by",
        lazy=True,
        foreign_keys="Contribution.recorded_by_user_id",
    )

    loans = db.relationship(
        "Loan",
        back_populates="borrower",
        lazy=True,
        foreign_keys="Loan.borrower_user_id",
    )

    approved_loans = db.relationship(
        "Loan",
        back_populates="approved_by",
        lazy=True,
        foreign_keys="Loan.approved_by_user_id",
    )

    rejected_loans = db.relationship(
        "Loan",
        back_populates="rejected_by",
        lazy=True,
        foreign_keys="Loan.rejected_by_user_id",
    )

    recorded_repayments = db.relationship(
        "LoanRepayment",
        back_populates="recorded_by",
        lazy=True,
        foreign_keys="LoanRepayment.recorded_by_user_id",
    )

    votes = db.relationship(
        "Vote",
        back_populates="user",
        lazy=True,
        foreign_keys="Vote.user_id",
    )

    audit_logs_actor = db.relationship(
        "AuditLog",
        foreign_keys="AuditLog.actor_user_id",
        back_populates="actor",
        lazy=True,
    )

    audit_logs_target_user = db.relationship(
        "AuditLog",
        foreign_keys="AuditLog.target_user_id",
        back_populates="target_user",
        lazy=True,
    )

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    @property
    def full_name(self):
        name = f"{self.first_name or ''} {self.last_name or ''}".strip()
        return name or self.username

    def active_membership_for_chama(self, chama_id):
        return Membership.query.filter_by(
            user_id=self.id,
            chama_id=chama_id,
            status=MembershipStatus.ACTIVE,
        ).first()

    def my_chamas_query(self):
        return Chama.query.join(Membership).filter(
            Membership.user_id == self.id,
            Membership.status == MembershipStatus.ACTIVE,
        )

    def can_access_chama(self, chama_id):
        if not self.is_active_account:
            return False
        membership = self.active_membership_for_chama(chama_id)
        return membership is not None

    def has_any_role(self, chama_id, roles):
        membership = self.active_membership_for_chama(chama_id)
        if not membership:
            return False
        return membership.role in roles

    def can_manage_onboarding(self, chama_id):
        return self.has_any_role(
            chama_id,
            {
                MembershipRole.ADMIN,
                MembershipRole.TREASURER,
                MembershipRole.SECRETARY,
            },
        )

    def to_dict_basic(self):
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.full_name,
            "username": self.username,
            "email": self.email,
            "phone_number": self.phone_number,
            "email_verified": self.email_verified,
            "phone_verified": self.phone_verified,
            "status": self.status.value,
            "is_deleted": self.is_deleted,
            "is_deactivated": self.is_deactivated,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<User {self.id} {self.email}>"


class Chama(db.Model, TimestampMixin):
    __tablename__ = "chamas"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(150), nullable=False, index=True)
    slug = db.Column(db.String(160), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)

    status = db.Column(
        db.Enum(ChamaStatus),
        default=ChamaStatus.ACTIVE,
        nullable=False,
        index=True,
    )

    currency = db.Column(db.String(10), default="KES", nullable=False)
    contribution_frequency = db.Column(db.String(50), nullable=True)
    base_contribution_amount = db.Column(db.Numeric(14, 2), nullable=True)

    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    memberships = db.relationship(
        "Membership",
        back_populates="chama",
        lazy=True,
        cascade="all, delete-orphan",
        foreign_keys="Membership.chama_id",
    )

    invites = db.relationship(
        "ChamaInvite",
        back_populates="chama",
        lazy=True,
        cascade="all, delete-orphan",
        foreign_keys="ChamaInvite.chama_id",
    )

    contributions = db.relationship(
        "Contribution",
        back_populates="chama",
        lazy=True,
        foreign_keys="Contribution.chama_id",
    )

    loans = db.relationship(
        "Loan",
        back_populates="chama",
        lazy=True,
        foreign_keys="Loan.chama_id",
    )

    polls = db.relationship(
        "Poll",
        back_populates="chama",
        lazy=True,
        foreign_keys="Poll.chama_id",
    )

    investments = db.relationship(
        "Investment",
        back_populates="chama",
        lazy=True,
        foreign_keys="Investment.chama_id",
    )

    def active_memberships_query(self):
        return Membership.query.filter_by(
            chama_id=self.id,
            status=MembershipStatus.ACTIVE,
        )

    def has_member(self, user_id):
        return self.active_memberships_query().filter_by(user_id=user_id).first() is not None

    def user_membership(self, user_id):
        return Membership.query.filter_by(
            chama_id=self.id,
            user_id=user_id,
        ).first()

    def user_can_access(self, user):
        return user.can_access_chama(self.id)

    def user_has_role(self, user, roles):
        return user.has_any_role(self.id, roles)

    def user_can_manage_onboarding(self, user):
        return user.can_manage_onboarding(self.id)

    def __repr__(self):
        return f"<Chama {self.id} {self.name}>"


class Membership(db.Model, TimestampMixin):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "chama_id", name="uq_membership_user_chama"),
        Index("ix_membership_user_chama_status", "user_id", "chama_id", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)

    role = db.Column(
        db.Enum(MembershipRole),
        default=MembershipRole.MEMBER,
        nullable=False,
        index=True,
    )

    status = db.Column(
        db.Enum(MembershipStatus),
        default=MembershipStatus.PENDING,
        nullable=False,
        index=True,
    )

    joined_at = db.Column(db.DateTime, nullable=True)
    left_at = db.Column(db.DateTime, nullable=True)

    invited_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approved_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    notes = db.Column(db.Text, nullable=True)

    user = db.relationship(
        "User",
        back_populates="memberships",
        foreign_keys=[user_id],
    )

    chama = db.relationship(
        "Chama",
        back_populates="memberships",
        foreign_keys=[chama_id],
    )

    inviter = db.relationship("User", foreign_keys=[invited_by_user_id])
    approver = db.relationship("User", foreign_keys=[approved_by_user_id])

    def activate(self, approved_by_user_id=None):
        self.status = MembershipStatus.ACTIVE
        self.joined_at = self.joined_at or datetime.utcnow()
        self.approved_by_user_id = approved_by_user_id
        self.left_at = None

    def suspend(self):
        self.status = MembershipStatus.SUSPENDED

    def remove(self):
        self.status = MembershipStatus.REMOVED
        self.left_at = datetime.utcnow()

    def leave(self):
        self.status = MembershipStatus.LEFT
        self.left_at = datetime.utcnow()

    @property
    def is_active(self):
        return self.status == MembershipStatus.ACTIVE

    @property
    def can_vote(self):
        return self.status == MembershipStatus.ACTIVE

    @property
    def can_borrow(self):
        return self.status == MembershipStatus.ACTIVE

    def has_any_role(self, roles):
        return self.is_active and self.role in roles

    def can_manage_onboarding(self):
        return self.has_any_role({
            MembershipRole.ADMIN,
            MembershipRole.TREASURER,
            MembershipRole.SECRETARY,
        })

    def can_record_financials(self):
        return self.has_any_role({
            MembershipRole.ADMIN,
            MembershipRole.TREASURER,
        })

    def can_create_polls(self):
        return self.has_any_role({
            MembershipRole.ADMIN,
            MembershipRole.SECRETARY,
        })

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "chama_id": self.chama_id,
            "role": self.role.value,
            "status": self.status.value,
            "joined_at": self.joined_at.isoformat() if self.joined_at else None,
            "left_at": self.left_at.isoformat() if self.left_at else None,
        }

    def __repr__(self):
        return f"<Membership user={self.user_id} chama={self.chama_id} role={self.role.value}>"


class ChamaInvite(db.Model, TimestampMixin):
    __tablename__ = "chama_invites"
    __table_args__ = (
        UniqueConstraint("chama_id", "email", "status", name="uq_pending_invite_per_email_chama"),
    )

    id = db.Column(db.Integer, primary_key=True)

    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    invited_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)

    email = db.Column(db.String(120), nullable=False, index=True)
    phone_number = db.Column(db.String(30), nullable=True, index=True)

    role_to_assign = db.Column(
        db.Enum(MembershipRole),
        default=MembershipRole.MEMBER,
        nullable=False,
    )

    status = db.Column(
        db.Enum(InviteStatus),
        default=InviteStatus.PENDING,
        nullable=False,
        index=True,
    )

    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)

    invited_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    accepted_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)

    chama = db.relationship(
        "Chama",
        back_populates="invites",
        foreign_keys=[chama_id],
    )

    invited_user = db.relationship(
        "User",
        back_populates="invites_received",
        foreign_keys=[invited_user_id],
    )

    invited_by = db.relationship("User", foreign_keys=[invited_by_user_id])

    @staticmethod
    def generate_token():
        return secrets.token_urlsafe(32)

    @staticmethod
    def default_expiry(days=7):
        return datetime.utcnow() + timedelta(days=days)

    @property
    def is_valid(self):
        return self.status == InviteStatus.PENDING and self.expires_at > datetime.utcnow()

    def mark_accepted(self, user_id=None):
        self.status = InviteStatus.ACCEPTED
        self.invited_user_id = user_id
        self.accepted_at = datetime.utcnow()

    def mark_expired(self):
        self.status = InviteStatus.EXPIRED

    def revoke(self):
        self.status = InviteStatus.REVOKED
        self.revoked_at = datetime.utcnow()

    def __repr__(self):
        return f"<ChamaInvite {self.email} chama={self.chama_id}>"


# =========================================================
# AUDIT LOG MODEL
# =========================================================

class AuditLog(db.Model, TimestampMixin):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_chama_id", "chama_id"),
        Index("ix_audit_logs_actor_user_id", "actor_user_id"),
        Index("ix_audit_logs_target_user_id", "target_user_id"),
        Index("ix_audit_logs_loan_id", "loan_id"),
        Index("ix_audit_logs_membership_id", "membership_id"),
    )

    id = db.Column(db.Integer, primary_key=True)

    action = db.Column(db.Enum(AuditAction), nullable=False, index=True)

    actor_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    target_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=True)
    loan_id = db.Column(db.Integer, db.ForeignKey("loans.id"), nullable=True)
    membership_id = db.Column(db.Integer, db.ForeignKey("memberships.id"), nullable=True)

    description = db.Column(db.Text, nullable=True)
    old_values = db.Column(db.JSON, nullable=True)
    new_values = db.Column(db.JSON, nullable=True)
    metadata_json = db.Column(db.JSON, nullable=True)

    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    actor = db.relationship(
        "User",
        foreign_keys=[actor_user_id],
        back_populates="audit_logs_actor",
    )

    target_user = db.relationship(
        "User",
        foreign_keys=[target_user_id],
        back_populates="audit_logs_target_user",
    )

    chama = db.relationship("Chama", foreign_keys=[chama_id])
    loan = db.relationship("Loan", foreign_keys=[loan_id])
    membership = db.relationship("Membership", foreign_keys=[membership_id])

    @classmethod
    def log(
        cls,
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
        ip_address=None,
        user_agent=None,
    ):
        entry = cls(
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
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.session.add(entry)
        db.session.flush()
        return entry

    def __repr__(self):
        return f"<AuditLog {self.id} action={self.action.value}>"


# =========================================================
# FINANCIAL MODELS
# =========================================================

class Contribution(db.Model, TimestampMixin):
    __tablename__ = "contributions"
    __table_args__ = (
        Index("ix_contribution_chama_user_date", "chama_id", "user_id", "contribution_date"),
    )

    id = db.Column(db.Integer, primary_key=True)

    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    amount = db.Column(db.Numeric(14, 2), nullable=False)
    contribution_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    recorded_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    payment_method = db.Column(db.String(50), nullable=True)
    reference_code = db.Column(db.String(100), nullable=True, index=True)
    notes = db.Column(db.Text, nullable=True)

    chama = db.relationship(
        "Chama",
        back_populates="contributions",
        foreign_keys=[chama_id],
    )

    user = db.relationship(
        "User",
        back_populates="contributions",
        foreign_keys=[user_id],
    )

    recorded_by = db.relationship(
        "User",
        back_populates="recorded_contributions",
        foreign_keys=[recorded_by_user_id],
    )

    def __repr__(self):
        return f"<Contribution {self.id} user={self.user_id} amount={self.amount}>"


class Loan(db.Model, TimestampMixin):
    __tablename__ = "loans"
    __table_args__ = (
        Index("ix_loan_chama_borrower_status", "chama_id", "borrower_user_id", "status"),
    )

    id = db.Column(db.Integer, primary_key=True)

    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    borrower_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    principal_amount = db.Column(db.Numeric(14, 2), nullable=False)
    interest_rate = db.Column(db.Numeric(5, 2), nullable=False, default=0.00)
    total_amount_due = db.Column(db.Numeric(14, 2), nullable=True)

    purpose = db.Column(db.Text, nullable=True)

    status = db.Column(
        db.Enum(LoanStatus),
        default=LoanStatus.PENDING,
        nullable=False,
        index=True,
    )

    applied_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    approved_at = db.Column(db.DateTime, nullable=True)
    disbursed_at = db.Column(db.DateTime, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)

    approved_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    rejected_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    rejection_reason = db.Column(db.Text, nullable=True)

    chama = db.relationship(
        "Chama",
        back_populates="loans",
        foreign_keys=[chama_id],
    )

    borrower = db.relationship(
        "User",
        back_populates="loans",
        foreign_keys=[borrower_user_id],
    )

    approved_by = db.relationship(
        "User",
        back_populates="approved_loans",
        foreign_keys=[approved_by_user_id],
    )

    rejected_by = db.relationship(
        "User",
        back_populates="rejected_loans",
        foreign_keys=[rejected_by_user_id],
    )

    repayments = db.relationship(
        "LoanRepayment",
        back_populates="loan",
        lazy=True,
        cascade="all, delete-orphan",
        foreign_keys="LoanRepayment.loan_id",
    )

    def calculate_total_due(self):
        principal = float(self.principal_amount or 0)
        interest = float(self.interest_rate or 0)
        total = principal + ((interest / 100) * principal)
        self.total_amount_due = round(total, 2)
        return self.total_amount_due

    @property
    def amount_repaid(self):
        return sum(float(r.amount) for r in self.repayments)

    @property
    def balance(self):
        total_due = float(self.total_amount_due or 0)
        return round(total_due - self.amount_repaid, 2)

    def refresh_repayment_status(self):
        if self.status in {LoanStatus.REJECTED, LoanStatus.CANCELLED}:
            return

        if self.total_amount_due is None:
            self.calculate_total_due()

        if self.balance <= 0 and self.total_amount_due is not None:
            self.status = LoanStatus.REPAID
        elif self.amount_repaid > 0:
            self.status = LoanStatus.PARTIALLY_REPAID
        elif self.disbursed_at is not None:
            self.status = LoanStatus.DISBURSED

    def __repr__(self):
        return f"<Loan {self.id} borrower={self.borrower_user_id} status={self.status.value}>"


class LoanRepayment(db.Model, TimestampMixin):
    __tablename__ = "loan_repayments"
    __table_args__ = (
        Index("ix_repayment_loan_date", "loan_id", "payment_date"),
    )

    id = db.Column(db.Integer, primary_key=True)

    loan_id = db.Column(db.Integer, db.ForeignKey("loans.id"), nullable=False, index=True)
    amount = db.Column(db.Numeric(14, 2), nullable=False)
    payment_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    recorded_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    payment_method = db.Column(db.String(50), nullable=True)
    reference_code = db.Column(db.String(100), nullable=True, index=True)
    notes = db.Column(db.Text, nullable=True)

    loan = db.relationship(
        "Loan",
        back_populates="repayments",
        foreign_keys=[loan_id],
    )

    recorded_by = db.relationship(
        "User",
        back_populates="recorded_repayments",
        foreign_keys=[recorded_by_user_id],
    )

    def __repr__(self):
        return f"<LoanRepayment {self.id} loan={self.loan_id} amount={self.amount}>"


# =========================================================
# VOTING MODELS
# =========================================================

class Poll(db.Model, TimestampMixin):
    __tablename__ = "polls"

    id = db.Column(db.Integer, primary_key=True)

    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)

    status = db.Column(
        db.Enum(PollStatus),
        default=PollStatus.DRAFT,
        nullable=False,
        index=True,
    )

    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    opens_at = db.Column(db.DateTime, nullable=True)
    closes_at = db.Column(db.DateTime, nullable=True)

    chama = db.relationship(
        "Chama",
        back_populates="polls",
        foreign_keys=[chama_id],
    )

    created_by = db.relationship("User", foreign_keys=[created_by_user_id])

    options = db.relationship(
        "PollOption",
        back_populates="poll",
        lazy=True,
        cascade="all, delete-orphan",
        foreign_keys="PollOption.poll_id",
    )

    votes = db.relationship(
        "Vote",
        back_populates="poll",
        lazy=True,
        cascade="all, delete-orphan",
        foreign_keys="Vote.poll_id",
    )

    @property
    def is_open(self):
        now = datetime.utcnow()
        return (
            self.status == PollStatus.OPEN
            and (self.opens_at is None or self.opens_at <= now)
            and (self.closes_at is None or self.closes_at >= now)
        )

    def __repr__(self):
        return f"<Poll {self.id} {self.title}>"


class PollOption(db.Model, TimestampMixin):
    __tablename__ = "poll_options"

    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey("polls.id"), nullable=False, index=True)
    option_text = db.Column(db.String(255), nullable=False)

    poll = db.relationship(
        "Poll",
        back_populates="options",
        foreign_keys=[poll_id],
    )

    def __repr__(self):
        return f"<PollOption {self.id} poll={self.poll_id}>"


class Vote(db.Model, TimestampMixin):
    __tablename__ = "votes"
    __table_args__ = (
        UniqueConstraint("poll_id", "user_id", name="uq_vote_poll_user"),
    )

    id = db.Column(db.Integer, primary_key=True)

    poll_id = db.Column(db.Integer, db.ForeignKey("polls.id"), nullable=False, index=True)
    option_id = db.Column(db.Integer, db.ForeignKey("poll_options.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    poll = db.relationship(
        "Poll",
        back_populates="votes",
        foreign_keys=[poll_id],
    )

    option = db.relationship("PollOption", foreign_keys=[option_id])

    user = db.relationship(
        "User",
        back_populates="votes",
        foreign_keys=[user_id],
    )

    def __repr__(self):
        return f"<Vote poll={self.poll_id} user={self.user_id}>"


# =========================================================
# INVESTMENT MODELS
# =========================================================

class Investment(db.Model, TimestampMixin):
    __tablename__ = "investments"
    __table_args__ = (
        Index("ix_investment_chama_status", "chama_id", "status"),
        Index("ix_investment_chama_type", "chama_id", "investment_type"),
    )

    id = db.Column(db.Integer, primary_key=True)

    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    name = db.Column(db.String(150), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)

    investment_type = db.Column(
        db.Enum(InvestmentType),
        default=InvestmentType.OTHER,
        nullable=False,
        index=True,
    )

    status = db.Column(
        db.Enum(InvestmentStatus),
        default=InvestmentStatus.PROPOSED,
        nullable=False,
        index=True,
    )

    principal_amount = db.Column(db.Numeric(14, 2), nullable=False)
    current_value = db.Column(db.Numeric(14, 2), nullable=True)
    expected_return_rate = db.Column(db.Numeric(5, 2), nullable=True)

    invested_at = db.Column(db.DateTime, nullable=True)
    maturity_date = db.Column(db.DateTime, nullable=True)
    closed_at = db.Column(db.DateTime, nullable=True)

    created_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    approved_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    chama = db.relationship(
        "Chama",
        back_populates="investments",
        foreign_keys=[chama_id],
    )

    created_by = db.relationship(
        "User",
        foreign_keys=[created_by_user_id],
        backref=db.backref("created_investments", lazy=True),
    )

    approved_by = db.relationship(
        "User",
        foreign_keys=[approved_by_user_id],
        backref=db.backref("approved_investments", lazy=True),
    )

    returns = db.relationship(
        "InvestmentReturn",
        back_populates="investment",
        lazy=True,
        cascade="all, delete-orphan",
        foreign_keys="InvestmentReturn.investment_id",
    )

    @property
    def total_returns(self):
        return round(sum(float(r.amount or 0) for r in self.returns), 2)

    @property
    def profit_or_loss(self):
        current = float(self.current_value or 0)
        principal = float(self.principal_amount or 0)
        returns_total = float(self.total_returns or 0)
        return round((current + returns_total) - principal, 2)

    @property
    def roi_percentage(self):
        principal = float(self.principal_amount or 0)
        if principal <= 0:
            return 0.0
        return round((self.profit_or_loss / principal) * 100, 2)

    def __repr__(self):
        return f"<Investment {self.id} {self.name} status={self.status.value}>"


class InvestmentReturn(db.Model, TimestampMixin):
    __tablename__ = "investment_returns"
    __table_args__ = (
        Index("ix_return_investment_date", "investment_id", "return_date"),
    )

    id = db.Column(db.Integer, primary_key=True)

    investment_id = db.Column(db.Integer, db.ForeignKey("investments.id"), nullable=False, index=True)
    amount = db.Column(db.Numeric(14, 2), nullable=False)

    return_type = db.Column(
        db.Enum(ReturnType),
        default=ReturnType.OTHER,
        nullable=False,
        index=True,
    )

    return_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    recorded_by_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    investment = db.relationship(
        "Investment",
        back_populates="returns",
        foreign_keys=[investment_id],
    )

    recorded_by = db.relationship(
        "User",
        foreign_keys=[recorded_by_user_id],
        backref=db.backref("recorded_investment_returns", lazy=True),
    )

    def __repr__(self):
        return f"<InvestmentReturn {self.id} investment={self.investment_id} amount={self.amount}>"