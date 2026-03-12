from datetime import datetime
from decimal import Decimal
from sqlalchemy import MetaData, CheckConstraint, UniqueConstraint
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db


# Optional naming convention for cleaner migrations
metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
        "ix": "ix_%(table_name)s_%(column_0_name)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
    }
)


def serialize_datetime(value):
    return value.isoformat() if value else None


def serialize_decimal(value):
    if value is None:
        return None
    return str(value)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True, index=True)
    email = db.Column(db.String(120), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(
        db.Enum("admin", "chairperson", "treasurer", "secretary", "member", name="user_roles"),
        nullable=False,
        default="member",
    )
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    profile = db.relationship("Profile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    memberships = db.relationship("Membership", back_populates="user", cascade="all, delete-orphan")
    balances = db.relationship("MemberBalance", back_populates="user", cascade="all, delete-orphan")
    contributions = db.relationship("Contribution", back_populates="user", cascade="all, delete-orphan")
    loans = db.relationship("Loan", back_populates="user", cascade="all, delete-orphan")
    repayments = db.relationship("Repayment", back_populates="user", cascade="all, delete-orphan")
    votes_created = db.relationship("Vote", back_populates="creator", cascade="all, delete-orphan")
    votes_cast = db.relationship("VoteCast", back_populates="voter", cascade="all, delete-orphan")
    feedbacks = db.relationship("Feedback", back_populates="user", cascade="all, delete-orphan")
    reports_generated = db.relationship("Report", back_populates="generated_by", cascade="all, delete-orphan")
    password_reset_tokens = db.relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")
    notifications = db.relationship("Notification", back_populates="user", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    expenses_recorded = db.relationship("Expense", back_populates="recorded_by", cascade="all, delete-orphan")
    investments_created = db.relationship("Investment", back_populates="created_by_user", cascade="all, delete-orphan")
    dividends_received = db.relationship("Dividend", back_populates="member", foreign_keys="Dividend.user_id", cascade="all, delete-orphan")
    dividends_declared = db.relationship("Dividend", back_populates="declared_by_user", foreign_keys="Dividend.declared_by", cascade="all, delete-orphan")

    def set_password(self, plain_password):
        self.password_hash = generate_password_hash(plain_password)

    def check_password(self, plain_password):
        return check_password_hash(self.password_hash, plain_password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "last_login": serialize_datetime(self.last_login),
            "is_active": self.is_active,
            "created_at": serialize_datetime(self.created_at),
            "updated_at": serialize_datetime(self.updated_at),
        }


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    token = db.Column(db.String(255), nullable=False, unique=True, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, nullable=False, default=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", back_populates="password_reset_tokens")

    def is_valid(self):
        return (not self.used) and (self.expires_at > datetime.utcnow())

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "expires_at": serialize_datetime(self.expires_at),
            "used": self.used,
            "used_at": serialize_datetime(self.used_at),
            "created_at": serialize_datetime(self.created_at),
        }


class Profile(db.Model):
    __tablename__ = "profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, unique=True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    phone = db.Column(db.String(30), unique=True)
    address = db.Column(db.Text)
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.Enum("male", "female", "other", name="gender_types"))
    id_number = db.Column(db.String(50), unique=True)
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", back_populates="profile")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "phone": self.phone,
            "address": self.address,
            "date_of_birth": self.date_of_birth.isoformat() if self.date_of_birth else None,
            "gender": self.gender,
            "id_number": self.id_number,
            "bio": self.bio,
            "avatar_url": self.avatar_url,
            "updated_at": serialize_datetime(self.updated_at),
        }


class Chama(db.Model):
    __tablename__ = "chamas"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False, unique=True, index=True)
    description = db.Column(db.Text)
    monthly_contribution = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    loan_interest_rate = db.Column(db.Numeric(5, 2), nullable=False, default=Decimal("10.00"))
    max_loan_amount = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    currency = db.Column(db.String(10), nullable=False, default="KES")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    memberships = db.relationship("Membership", back_populates="chama", cascade="all, delete-orphan")
    balances = db.relationship("MemberBalance", back_populates="chama", cascade="all, delete-orphan")
    contributions = db.relationship("Contribution", back_populates="chama", cascade="all, delete-orphan")
    loans = db.relationship("Loan", back_populates="chama", cascade="all, delete-orphan")
    votes = db.relationship("Vote", back_populates="chama", cascade="all, delete-orphan")
    feedbacks = db.relationship("Feedback", back_populates="chama", cascade="all, delete-orphan")
    reports = db.relationship("Report", back_populates="chama", cascade="all, delete-orphan")
    notifications = db.relationship("Notification", back_populates="chama", cascade="all, delete-orphan")
    audit_logs = db.relationship("AuditLog", back_populates="chama", cascade="all, delete-orphan")
    investments = db.relationship("Investment", back_populates="chama", cascade="all, delete-orphan")
    expenses = db.relationship("Expense", back_populates="chama", cascade="all, delete-orphan")
    dividends = db.relationship("Dividend", back_populates="chama", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("monthly_contribution >= 0", name="check_chama_monthly_contribution_non_negative"),
        CheckConstraint("loan_interest_rate >= 0", name="check_chama_loan_interest_rate_non_negative"),
        CheckConstraint("max_loan_amount >= 0", name="check_chama_max_loan_amount_non_negative"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "monthly_contribution": serialize_decimal(self.monthly_contribution),
            "loan_interest_rate": serialize_decimal(self.loan_interest_rate),
            "max_loan_amount": serialize_decimal(self.max_loan_amount),
            "currency": self.currency,
            "is_active": self.is_active,
            "created_at": serialize_datetime(self.created_at),
            "updated_at": serialize_datetime(self.updated_at),
        }


class Membership(db.Model):
    """
    This table represents the member record of a user inside a chama.
    So instead of a separate Member model, Membership is the member record.
    """

    __tablename__ = "memberships"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False)
    role = db.Column(
        db.Enum("chairperson", "treasurer", "secretary", "member", name="membership_roles"),
        nullable=False,
        default="member",
    )
    status = db.Column(
        db.Enum("active", "inactive", "pending", "suspended", name="membership_statuses"),
        nullable=False,
        default="active",
    )
    monthly_contribution = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_contribution_date = db.Column(db.DateTime)

    user = db.relationship("User", back_populates="memberships")
    chama = db.relationship("Chama", back_populates="memberships")

    __table_args__ = (
        UniqueConstraint("user_id", "chama_id", name="uq_memberships_user_id_chama_id"),
        CheckConstraint("monthly_contribution >= 0", name="check_membership_monthly_contribution_non_negative"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "chama_id": self.chama_id,
            "role": self.role,
            "status": self.status,
            "monthly_contribution": serialize_decimal(self.monthly_contribution),
            "joined_at": serialize_datetime(self.joined_at),
            "last_contribution_date": serialize_datetime(self.last_contribution_date),
            "user_name": self.user.username if self.user else None,
            "chama_name": self.chama.name if self.chama else None,
        }


class MemberBalance(db.Model):
    """
    Dedicated balance model.
    This stores a running financial snapshot for each member inside a chama.
    Update it in your service layer whenever contributions, loans, repayments,
    dividends, or penalties change.
    """

    __tablename__ = "member_balances"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False)
    total_contributed = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    total_loans_received = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    total_repaid = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    total_dividends_received = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    penalties = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    available_savings = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    outstanding_loan_balance = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    net_position = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship("User", back_populates="balances")
    chama = db.relationship("Chama", back_populates="balances")

    __table_args__ = (
        UniqueConstraint("user_id", "chama_id", name="uq_member_balances_user_id_chama_id"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "chama_id": self.chama_id,
            "total_contributed": serialize_decimal(self.total_contributed),
            "total_loans_received": serialize_decimal(self.total_loans_received),
            "total_repaid": serialize_decimal(self.total_repaid),
            "total_dividends_received": serialize_decimal(self.total_dividends_received),
            "penalties": serialize_decimal(self.penalties),
            "available_savings": serialize_decimal(self.available_savings),
            "outstanding_loan_balance": serialize_decimal(self.outstanding_loan_balance),
            "net_position": serialize_decimal(self.net_position),
            "updated_at": serialize_datetime(self.updated_at),
            "user_name": self.user.username if self.user else None,
            "chama_name": self.chama.name if self.chama else None,
        }


class Contribution(db.Model):
    __tablename__ = "contributions"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    contribution_type = db.Column(
        db.Enum("regular", "penalty", "registration", "special", name="contribution_types"),
        nullable=False,
        default="regular",
    )
    contribution_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    payment_method = db.Column(
        db.Enum("mpesa", "bank", "cash", "mobile_money", name="contribution_payment_methods"),
        nullable=False,
        default="mpesa",
    )
    reference = db.Column(db.String(120))
    transaction_id = db.Column(db.String(120), unique=True)
    status = db.Column(
        db.Enum("pending", "confirmed", "failed", "cancelled", name="contribution_statuses"),
        nullable=False,
        default="pending",
    )
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    confirmed_at = db.Column(db.DateTime)

    user = db.relationship("User", back_populates="contributions")
    chama = db.relationship("Chama", back_populates="contributions")

    __table_args__ = (
        CheckConstraint("amount > 0", name="check_contribution_amount_positive"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "chama_id": self.chama_id,
            "user_id": self.user_id,
            "amount": serialize_decimal(self.amount),
            "contribution_type": self.contribution_type,
            "contribution_date": serialize_datetime(self.contribution_date),
            "payment_method": self.payment_method,
            "reference": self.reference,
            "transaction_id": self.transaction_id,
            "status": self.status,
            "notes": self.notes,
            "created_at": serialize_datetime(self.created_at),
            "confirmed_at": serialize_datetime(self.confirmed_at),
            "user_name": self.user.username if self.user else None,
            "chama_name": self.chama.name if self.chama else None,
        }


class Loan(db.Model):
    __tablename__ = "loans"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    interest_rate = db.Column(db.Numeric(5, 2), nullable=False)
    term_months = db.Column(db.Integer, nullable=False, default=6)
    purpose = db.Column(db.Text)
    status = db.Column(
        db.Enum(
            "requested",
            "approved",
            "rejected",
            "disbursed",
            "active",
            "completed",
            "defaulted",
            name="loan_statuses",
        ),
        nullable=False,
        default="requested",
    )
    requested_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    disbursed_at = db.Column(db.DateTime)
    due_date = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    total_repayment = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    monthly_repayment = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    amount_paid = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    remaining_balance = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))

    user = db.relationship("User", back_populates="loans")
    chama = db.relationship("Chama", back_populates="loans")
    repayments = db.relationship("Repayment", back_populates="loan", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("amount > 0", name="check_loan_amount_positive"),
        CheckConstraint("interest_rate >= 0", name="check_loan_interest_rate_non_negative"),
        CheckConstraint("term_months > 0", name="check_loan_term_months_positive"),
    )

    def calculate_repayment(self):
        monthly_rate = Decimal(self.interest_rate) / Decimal("100") / Decimal("12")
        principal = Decimal(self.amount)
        total = principal * (Decimal("1") + (monthly_rate * Decimal(self.term_months)))
        self.total_repayment = total.quantize(Decimal("0.01"))
        self.monthly_repayment = (self.total_repayment / Decimal(self.term_months)).quantize(Decimal("0.01"))
        self.remaining_balance = self.total_repayment - Decimal(self.amount_paid or 0)

    def to_dict(self):
        return {
            "id": self.id,
            "chama_id": self.chama_id,
            "user_id": self.user_id,
            "amount": serialize_decimal(self.amount),
            "interest_rate": serialize_decimal(self.interest_rate),
            "term_months": self.term_months,
            "purpose": self.purpose,
            "status": self.status,
            "requested_at": serialize_datetime(self.requested_at),
            "approved_at": serialize_datetime(self.approved_at),
            "disbursed_at": serialize_datetime(self.disbursed_at),
            "due_date": serialize_datetime(self.due_date),
            "completed_at": serialize_datetime(self.completed_at),
            "created_at": serialize_datetime(self.created_at),
            "updated_at": serialize_datetime(self.updated_at),
            "total_repayment": serialize_decimal(self.total_repayment),
            "monthly_repayment": serialize_decimal(self.monthly_repayment),
            "amount_paid": serialize_decimal(self.amount_paid),
            "remaining_balance": serialize_decimal(self.remaining_balance),
            "user_name": self.user.username if self.user else None,
            "chama_name": self.chama.name if self.chama else None,
        }


class Repayment(db.Model):
    __tablename__ = "repayments"

    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey("loans.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    amount_paid = db.Column(db.Numeric(12, 2), nullable=False)
    payment_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    payment_method = db.Column(
        db.Enum("mpesa", "bank", "cash", "mobile_money", name="repayment_payment_methods"),
        nullable=False,
        default="mpesa",
    )
    reference = db.Column(db.String(120))
    transaction_id = db.Column(db.String(120), unique=True)
    status = db.Column(
        db.Enum("pending", "confirmed", "failed", "cancelled", name="repayment_statuses"),
        nullable=False,
        default="pending",
    )
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    confirmed_at = db.Column(db.DateTime)

    user = db.relationship("User", back_populates="repayments")
    loan = db.relationship("Loan", back_populates="repayments")

    __table_args__ = (
        CheckConstraint("amount_paid > 0", name="check_repayment_amount_paid_positive"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "loan_id": self.loan_id,
            "user_id": self.user_id,
            "amount_paid": serialize_decimal(self.amount_paid),
            "payment_date": serialize_datetime(self.payment_date),
            "payment_method": self.payment_method,
            "reference": self.reference,
            "transaction_id": self.transaction_id,
            "status": self.status,
            "notes": self.notes,
            "created_at": serialize_datetime(self.created_at),
            "confirmed_at": serialize_datetime(self.confirmed_at),
            "user_name": self.user.username if self.user else None,
        }


class Vote(db.Model):
    """
    In your design, this model acts as the poll.
    VoteCast then represents the actual vote submitted by a member.
    """

    __tablename__ = "votes"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    topic = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    vote_type = db.Column(
        db.Enum("yes_no", "multiple_choice", "election", name="vote_types"),
        nullable=False,
        default="yes_no",
    )
    status = db.Column(
        db.Enum("open", "closed", "cancelled", name="vote_statuses"),
        nullable=False,
        default="open",
    )
    closed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    chama = db.relationship("Chama", back_populates="votes")
    creator = db.relationship("User", back_populates="votes_created")
    options = db.relationship("VoteOption", back_populates="vote", cascade="all, delete-orphan")
    casts = db.relationship("VoteCast", back_populates="vote", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "chama_id": self.chama_id,
            "created_by": self.created_by,
            "topic": self.topic,
            "description": self.description,
            "vote_type": self.vote_type,
            "status": self.status,
            "closed_at": serialize_datetime(self.closed_at),
            "created_at": serialize_datetime(self.created_at),
            "updated_at": serialize_datetime(self.updated_at),
            "creator_name": self.creator.username if self.creator else None,
            "options": [option.to_dict() for option in self.options],
            "total_votes": len(self.casts),
        }


class VoteOption(db.Model):
    __tablename__ = "vote_options"

    id = db.Column(db.Integer, primary_key=True)
    vote_id = db.Column(db.Integer, db.ForeignKey("votes.id"), nullable=False, index=True)
    option_text = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    vote = db.relationship("Vote", back_populates="options")
    casts = db.relationship("VoteCast", back_populates="option", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("vote_id", "option_text", name="uq_vote_options_vote_id_option_text"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "vote_id": self.vote_id,
            "option_text": self.option_text,
            "description": self.description,
            "created_at": serialize_datetime(self.created_at),
            "vote_count": len(self.casts),
        }


class VoteCast(db.Model):
    __tablename__ = "vote_casts"

    id = db.Column(db.Integer, primary_key=True)
    vote_id = db.Column(db.Integer, db.ForeignKey("votes.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    option_id = db.Column(db.Integer, db.ForeignKey("vote_options.id"), nullable=False, index=True)
    anonymous = db.Column(db.Boolean, nullable=False, default=True)
    voted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    vote = db.relationship("Vote", back_populates="casts")
    voter = db.relationship("User", back_populates="votes_cast")
    option = db.relationship("VoteOption", back_populates="casts")

    __table_args__ = (
        UniqueConstraint("vote_id", "user_id", name="uq_vote_casts_vote_id_user_id"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "vote_id": self.vote_id,
            "user_id": self.user_id,
            "option_id": self.option_id,
            "anonymous": self.anonymous,
            "voted_at": serialize_datetime(self.voted_at),
            "option_text": self.option.option_text if self.option else None,
        }


class Investment(db.Model):
    __tablename__ = "investments"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    investment_type = db.Column(
        db.Enum("business", "real_estate", "sacco", "shares", "bonds", "money_market", "other", name="investment_types"),
        nullable=False,
        default="other",
    )
    amount_invested = db.Column(db.Numeric(12, 2), nullable=False)
    current_value = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    expected_return_rate = db.Column(db.Numeric(5, 2), nullable=False, default=Decimal("0.00"))
    realized_profit_loss = db.Column(db.Numeric(12, 2), nullable=False, default=Decimal("0.00"))
    status = db.Column(
        db.Enum("planned", "active", "matured", "closed", "loss", name="investment_statuses"),
        nullable=False,
        default="active",
    )
    start_date = db.Column(db.Date)
    maturity_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    chama = db.relationship("Chama", back_populates="investments")
    created_by_user = db.relationship("User", back_populates="investments_created")
    dividends = db.relationship("Dividend", back_populates="investment", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("amount_invested >= 0", name="check_investment_amount_invested_non_negative"),
        CheckConstraint("current_value >= 0", name="check_investment_current_value_non_negative"),
        CheckConstraint("expected_return_rate >= 0", name="check_investment_expected_return_rate_non_negative"),
    )

    @property
    def unrealized_profit_loss(self):
        if self.current_value is None or self.amount_invested is None:
            return Decimal("0.00")
        return Decimal(self.current_value) - Decimal(self.amount_invested)

    def to_dict(self):
        return {
            "id": self.id,
            "chama_id": self.chama_id,
            "created_by": self.created_by,
            "title": self.title,
            "description": self.description,
            "investment_type": self.investment_type,
            "amount_invested": serialize_decimal(self.amount_invested),
            "current_value": serialize_decimal(self.current_value),
            "expected_return_rate": serialize_decimal(self.expected_return_rate),
            "realized_profit_loss": serialize_decimal(self.realized_profit_loss),
            "unrealized_profit_loss": serialize_decimal(self.unrealized_profit_loss),
            "status": self.status,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "maturity_date": self.maturity_date.isoformat() if self.maturity_date else None,
            "created_at": serialize_datetime(self.created_at),
            "updated_at": serialize_datetime(self.updated_at),
            "chama_name": self.chama.name if self.chama else None,
            "created_by_name": self.created_by_user.username if self.created_by_user else None,
        }


class Expense(db.Model):
    __tablename__ = "expenses"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    recorded_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(
        db.Enum(
            "operations",
            "meeting",
            "transport",
            "communication",
            "bank_charges",
            "investment",
            "legal",
            "other",
            name="expense_categories",
        ),
        nullable=False,
        default="operations",
    )
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    expense_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    payment_method = db.Column(
        db.Enum("mpesa", "bank", "cash", "mobile_money", name="expense_payment_methods"),
        nullable=False,
        default="cash",
    )
    reference = db.Column(db.String(120))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    chama = db.relationship("Chama", back_populates="expenses")
    recorded_by = db.relationship("User", back_populates="expenses_recorded")

    __table_args__ = (
        CheckConstraint("amount > 0", name="check_expense_amount_positive"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "chama_id": self.chama_id,
            "recorded_by_id": self.recorded_by_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "amount": serialize_decimal(self.amount),
            "expense_date": serialize_datetime(self.expense_date),
            "payment_method": self.payment_method,
            "reference": self.reference,
            "notes": self.notes,
            "created_at": serialize_datetime(self.created_at),
            "recorded_by_name": self.recorded_by.username if self.recorded_by else None,
            "chama_name": self.chama.name if self.chama else None,
        }


class Dividend(db.Model):
    __tablename__ = "dividends"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    investment_id = db.Column(db.Integer, db.ForeignKey("investments.id"), nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    declared_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    source_type = db.Column(
        db.Enum("investment_profit", "surplus", "interest_income", "other", name="dividend_source_types"),
        nullable=False,
        default="investment_profit",
    )
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    period_start = db.Column(db.DateTime)
    period_end = db.Column(db.DateTime)
    status = db.Column(
        db.Enum("pending", "approved", "paid", "cancelled", name="dividend_statuses"),
        nullable=False,
        default="pending",
    )
    notes = db.Column(db.Text)
    declared_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)

    chama = db.relationship("Chama", back_populates="dividends")
    investment = db.relationship("Investment", back_populates="dividends")
    member = db.relationship("User", back_populates="dividends_received", foreign_keys=[user_id])
    declared_by_user = db.relationship("User", back_populates="dividends_declared", foreign_keys=[declared_by])

    __table_args__ = (
        CheckConstraint("amount >= 0", name="check_dividend_amount_non_negative"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "chama_id": self.chama_id,
            "investment_id": self.investment_id,
            "user_id": self.user_id,
            "declared_by": self.declared_by,
            "source_type": self.source_type,
            "amount": serialize_decimal(self.amount),
            "period_start": serialize_datetime(self.period_start),
            "period_end": serialize_datetime(self.period_end),
            "status": self.status,
            "notes": self.notes,
            "declared_at": serialize_datetime(self.declared_at),
            "paid_at": serialize_datetime(self.paid_at),
            "member_name": self.member.username if self.member else None,
            "declared_by_name": self.declared_by_user.username if self.declared_by_user else None,
            "investment_title": self.investment.title if self.investment else None,
            "chama_name": self.chama.name if self.chama else None,
        }


class Feedback(db.Model):
    __tablename__ = "feedback"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(
        db.Enum("general", "complaint", "suggestion", "appreciation", name="feedback_categories"),
        nullable=False,
        default="general",
    )
    status = db.Column(
        db.Enum("new", "read", "addressed", "closed", name="feedback_statuses"),
        nullable=False,
        default="new",
    )
    response = db.Column(db.Text)
    responded_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    chama = db.relationship("Chama", back_populates="feedbacks")
    user = db.relationship("User", back_populates="feedbacks")

    def to_dict(self):
        return {
            "id": self.id,
            "chama_id": self.chama_id,
            "user_id": self.user_id,
            "message": self.message,
            "category": self.category,
            "status": self.status,
            "response": self.response,
            "responded_at": serialize_datetime(self.responded_at),
            "created_at": serialize_datetime(self.created_at),
            "updated_at": serialize_datetime(self.updated_at),
            "user_name": self.user.username if self.user else None,
            "chama_name": self.chama.name if self.chama else None,
        }


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    report_type = db.Column(
        db.Enum("contributions", "loans", "members", "financial", "voting", "investments", "expenses", "dividends", name="report_types"),
        nullable=False,
    )
    title = db.Column(db.String(200), nullable=False)
    data = db.Column(db.JSON)
    parameters = db.Column(db.JSON)
    file_path = db.Column(db.Text)
    generated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    period_start = db.Column(db.DateTime)
    period_end = db.Column(db.DateTime)

    chama = db.relationship("Chama", back_populates="reports")
    generated_by = db.relationship("User", back_populates="reports_generated")

    def to_dict(self):
        return {
            "id": self.id,
            "chama_id": self.chama_id,
            "user_id": self.user_id,
            "report_type": self.report_type,
            "title": self.title,
            "data": self.data,
            "parameters": self.parameters,
            "file_path": self.file_path,
            "generated_at": serialize_datetime(self.generated_at),
            "period_start": serialize_datetime(self.period_start),
            "period_end": serialize_datetime(self.period_end),
            "generated_by_name": self.generated_by.username if self.generated_by else None,
            "chama_name": self.chama.name if self.chama else None,
        }


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=True, index=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(
        db.Enum("info", "warning", "success", "error", "reminder", name="notification_types"),
        nullable=False,
        default="info",
    )
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    action_url = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    read_at = db.Column(db.DateTime)

    user = db.relationship("User", back_populates="notifications")
    chama = db.relationship("Chama", back_populates="notifications")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "chama_id": self.chama_id,
            "title": self.title,
            "message": self.message,
            "notification_type": self.notification_type,
            "is_read": self.is_read,
            "action_url": self.action_url,
            "created_at": serialize_datetime(self.created_at),
            "read_at": serialize_datetime(self.read_at),
            "chama_name": self.chama.name if self.chama else None,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    chama_id = db.Column(db.Integer, db.ForeignKey("chamas.id"), nullable=True, index=True)
    action = db.Column(db.String(120), nullable=False)
    resource_type = db.Column(db.String(120), nullable=False)
    resource_id = db.Column(db.Integer)
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(100))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", back_populates="audit_logs")
    chama = db.relationship("Chama", back_populates="audit_logs")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "chama_id": self.chama_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "details": self.details,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": serialize_datetime(self.created_at),
            "user_name": self.user.username if self.user else None,
            "chama_name": self.chama.name if self.chama else None,
        }