from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import MetaData, Text, Float, Integer, TIMESTAMP, Date, DateTime, Enum, JSON, ForeignKey, String, Boolean
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy_serializer import SerializerMixin

metadata = MetaData(naming_convention={
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
})

db = SQLAlchemy(metadata=metadata)

class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    email = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.Text, default="member")
    last_login = db.Column(db.TIMESTAMP)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    profile = db.relationship('Profile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    memberships = db.relationship('Membership', back_populates='user', cascade="all, delete-orphan")
    contributions = db.relationship('Contribution', back_populates='user', cascade="all, delete-orphan")
    loans = db.relationship('Loan', back_populates='user', cascade="all, delete-orphan")
    repayments = db.relationship('Repayment', back_populates='user', cascade="all, delete-orphan")
    votes_created = db.relationship('Vote', back_populates='creator', cascade="all, delete-orphan")
    votes_cast = db.relationship('VoteCast', back_populates='voter', cascade="all, delete-orphan")
    feedbacks = db.relationship('Feedback', back_populates='user', cascade="all, delete-orphan")
    reports_generated = db.relationship('Report', back_populates='generated_by', cascade="all, delete-orphan")
    password_reset_tokens = db.relationship('PasswordResetToken', back_populates='user', cascade="all, delete-orphan")
    notifications = db.relationship('Notification', back_populates='user', cascade="all, delete-orphan")
    audit_logs = db.relationship('AuditLog', back_populates='user', cascade="all, delete-orphan")

    serialize_rules = (
        '-password',
        '-profile.user',
        '-memberships.user',
        '-contributions.user',
        '-loans.user',
        '-repayments.user',
        '-votes_created.creator',
        '-votes_cast.voter',
        '-feedbacks.user',
        '-reports_generated.generated_by',
        '-password_reset_tokens.user',
        '-notifications.user',
        '-audit_logs.user',
    )

    def set_password(self, plain_password):
        # .decode('utf-8') for production
        self.password = generate_password_hash(plain_password).decode('utf-8')

    def check_password(self, plain_password):
        return check_password_hash(self.password, plain_password)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active
        }

class PasswordResetToken(db.Model, SerializerMixin):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(255), nullable=False, unique=True)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    expires_at = db.Column(db.TIMESTAMP, nullable=False)
    used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.TIMESTAMP)

    #Used back_populates instead of backref for total control
    user = db.relationship('User', back_populates='password_reset_tokens')

    serialize_rules = ('-user', '-token')

    def is_valid(self):
        return not self.used and self.expires_at > datetime.utcnow()

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'used': self.used,
            'used_at': self.used_at.isoformat() if self.used_at else None
        }

class Profile(db.Model, SerializerMixin):
    __tablename__ = "profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    first_name = db.Column(db.Text)
    last_name = db.Column(db.Text)
    phone = db.Column(db.Text)
    address = db.Column(db.Text)
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.Enum('male', 'female', 'other', name='gender_types'))
    id_number = db.Column(db.Text)
    bio = db.Column(db.Text)
    avatar_url = db.Column(db.Text)
    updated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', back_populates='profile')

    serialize_rules = (
        '-user',
        '-user_id',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'phone': self.phone,
            'address': self.address,
            'date_of_birth': self.date_of_birth.isoformat() if self.date_of_birth else None,
            'gender': self.gender,
            'id_number': self.id_number,
            'bio': self.bio,
            'avatar_url': self.avatar_url
        }

class Chama(db.Model, SerializerMixin):
    __tablename__ = "chamas"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False, unique=True)
    description = db.Column(db.Text)
    monthly_contribution = db.Column(db.Float, default=0.0)
    loan_interest_rate = db.Column(db.Float, default=10.0)
    max_loan_amount = db.Column(db.Float, default=0.0)
    currency = db.Column(db.Text, default='KES')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    memberships = db.relationship('Membership', back_populates='chama', cascade="all, delete-orphan")
    contributions = db.relationship('Contribution', back_populates='chama', cascade="all, delete-orphan")
    loans = db.relationship('Loan', back_populates='chama', cascade="all, delete-orphan")
    votes = db.relationship('Vote', back_populates='chama', cascade="all, delete-orphan")
    feedbacks = db.relationship('Feedback', back_populates='chama', cascade="all, delete-orphan")
    reports = db.relationship('Report', back_populates='chama', cascade="all, delete-orphan")

    serialize_rules = (
        '-memberships.chama',
        '-contributions.chama',
        '-loans.chama',
        '-votes.chama',
        '-feedbacks.chama',
        '-reports.chama',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'monthly_contribution': self.monthly_contribution,
            'loan_interest_rate': self.loan_interest_rate,
            'max_loan_amount': self.max_loan_amount,
            'currency': self.currency,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Membership(db.Model, SerializerMixin):
    __tablename__ = "memberships"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    role = db.Column(
        db.Enum('chairperson', 'treasurer', 'secretary', 'member', name='member_role'),
        nullable=False,
        default='member'
    )
    joined_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    status = db.Column(
        db.Enum('active', 'inactive', 'pending', 'suspended', name='member_status'),
        default='active'
    )
    monthly_contribution = db.Column(db.Float)
    last_contribution_date = db.Column(db.TIMESTAMP)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'chama_id', name='unique_membership'),
    )

    # Relationships
    user = db.relationship('User', back_populates='memberships')
    chama = db.relationship('Chama', back_populates='memberships')

    serialize_rules = (
        '-user.memberships',
        '-user.contributions',
        '-user.loans',
        '-user.repayments',
        '-user.votes_created',
        '-user.votes_cast',
        '-user.feedbacks',
        '-user.reports_generated',
        '-chama.memberships',
        '-chama.contributions',
        '-chama.loans',
        '-chama.votes',
        '-chama.feedbacks',
        '-chama.reports',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'chama_id': self.chama_id,
            'role': self.role,
            'joined_at': self.joined_at.isoformat() if self.joined_at else None,
            'status': self.status,
            'monthly_contribution': self.monthly_contribution,
            'last_contribution_date': self.last_contribution_date.isoformat() if self.last_contribution_date else None,
            'user': self.user.to_dict() if self.user else None,
            'chama_name': self.chama.name if self.chama else None
        }

class Contribution(db.Model, SerializerMixin):
    __tablename__ = "contributions"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    contribution_date = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    payment_method = db.Column(db.Enum('mpesa', 'bank', 'cash', 'mobile_money', name='payment_methods'))
    reference = db.Column(db.Text)
    transaction_id = db.Column(db.Text, unique=True)
    status = db.Column(
        db.Enum('pending', 'confirmed', 'failed', 'cancelled', name='contribution_status'),
        default='pending'
    )
    notes = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    confirmed_at = db.Column(db.TIMESTAMP)

    # Relationships
    user = db.relationship('User', back_populates='contributions')
    chama = db.relationship('Chama', back_populates='contributions')

    serialize_rules = (
        '-user.contributions',
        '-user.memberships',
        '-user.loans',
        '-user.repayments',
        '-chama.contributions',
        '-chama.memberships',
        '-chama.loans',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'chama_id': self.chama_id,
            'user_id': self.user_id,
            'amount': self.amount,
            'contribution_date': self.contribution_date.isoformat() if self.contribution_date else None,
            'payment_method': self.payment_method,
            'reference': self.reference,
            'transaction_id': self.transaction_id,
            'status': self.status,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'confirmed_at': self.confirmed_at.isoformat() if self.confirmed_at else None,
            'user_name': self.user.username if self.user else None,
            'chama_name': self.chama.name if self.chama else None
        }

class Loan(db.Model, SerializerMixin):
    __tablename__ = "loans"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    term_months = db.Column(db.Integer, default=6)
    purpose = db.Column(db.Text)
    status = db.Column(
        db.Enum('requested', 'approved', 'rejected', 'disbursed', 'active', 'completed', 'defaulted', name='loan_status'),
        default='requested'
    )
    requested_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    approved_at = db.Column(db.TIMESTAMP)
    disbursed_at = db.Column(db.TIMESTAMP)
    due_date = db.Column(db.DateTime)
    completed_at = db.Column(db.TIMESTAMP)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Calculated fields
    total_repayment = db.Column(db.Float)
    monthly_repayment = db.Column(db.Float)
    amount_paid = db.Column(db.Float, default=0.0)
    remaining_balance = db.Column(db.Float)

    # Relationships
    user = db.relationship('User', back_populates='loans')
    chama = db.relationship('Chama', back_populates='loans')
    repayments = db.relationship('Repayment', back_populates='loan', cascade="all, delete-orphan")

    serialize_rules = (
        '-user.loans',
        '-user.contributions',
        '-user.memberships',
        '-chama.loans',
        '-chama.contributions',
        '-chama.memberships',
        '-repayments.loan',
    )

    def calculate_repayment(self):
        """Calculate total repayment and monthly installment"""
        monthly_rate = self.interest_rate / 100 / 12
        self.total_repayment = self.amount * (1 + monthly_rate * self.term_months)
        self.monthly_repayment = self.total_repayment / self.term_months
        self.remaining_balance = self.total_repayment

    def to_dict(self):
        return {
            'id': self.id,
            'chama_id': self.chama_id,
            'user_id': self.user_id,
            'amount': self.amount,
            'interest_rate': self.interest_rate,
            'term_months': self.term_months,
            'purpose': self.purpose,
            'status': self.status,
            'requested_at': self.requested_at.isoformat() if self.requested_at else None,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'disbursed_at': self.disbursed_at.isoformat() if self.disbursed_at else None,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_repayment': self.total_repayment,
            'monthly_repayment': self.monthly_repayment,
            'amount_paid': self.amount_paid,
            'remaining_balance': self.remaining_balance,
            'user_name': self.user.username if self.user else None,
            'chama_name': self.chama.name if self.chama else None
        }

class Repayment(db.Model, SerializerMixin):
    __tablename__ = "repayments"

    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loans.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount_paid = db.Column(db.Float, nullable=False)
    payment_date = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    payment_method = db.Column(db.Enum('mpesa', 'bank', 'cash', 'mobile_money', name='payment_methods'))
    reference = db.Column(db.Text)
    transaction_id = db.Column(db.Text, unique=True)
    status = db.Column(
        db.Enum('pending', 'confirmed', 'failed', 'cancelled', name='repayment_status'),
        default='pending'
    )
    notes = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    confirmed_at = db.Column(db.TIMESTAMP)

    # Relationships
    user = db.relationship('User', back_populates='repayments')
    loan = db.relationship('Loan', back_populates='repayments')

    serialize_rules = (
        '-user.repayments',
        '-user.contributions',
        '-user.loans',
        '-loan.repayments',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'loan_id': self.loan_id,
            'user_id': self.user_id,
            'amount_paid': self.amount_paid,
            'payment_date': self.payment_date.isoformat() if self.payment_date else None,
            'payment_method': self.payment_method,
            'reference': self.reference,
            'transaction_id': self.transaction_id,
            'status': self.status,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'confirmed_at': self.confirmed_at.isoformat() if self.confirmed_at else None,
            'user_name': self.user.username if self.user else None
        }

class Vote(db.Model, SerializerMixin):
    __tablename__ = "votes"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    topic = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    vote_type = db.Column(db.Enum('yes_no', 'multiple_choice', 'election', name='vote_types'), default='yes_no')
    status = db.Column(db.Enum('open', 'closed', 'cancelled', name='vote_status'), default='open')
    closed_at = db.Column(db.TIMESTAMP)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    chama = db.relationship('Chama', back_populates='votes')
    creator = db.relationship('User', back_populates='votes_created')
    options = db.relationship('VoteOption', back_populates='vote', cascade="all, delete-orphan")
    casts = db.relationship('VoteCast', back_populates='vote', cascade="all, delete-orphan")

    serialize_rules = (
        '-chama.votes',
        '-creator.votes_created',
        '-options.vote',
        '-casts.vote',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'chama_id': self.chama_id,
            'created_by': self.created_by,
            'topic': self.topic,
            'description': self.description,
            'vote_type': self.vote_type,
            'status': self.status,
            'closed_at': self.closed_at.isoformat() if self.closed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'creator_name': self.creator.username if self.creator else None,
            'options': [option.to_dict() for option in self.options] if self.options else [],
            'total_votes': len(self.casts) if self.casts else 0
        }


class VoteOption(db.Model, SerializerMixin):
    __tablename__ = "vote_options"

    id = db.Column(db.Integer, primary_key=True)
    vote_id = db.Column(db.Integer, db.ForeignKey('votes.id'), nullable=False)
    option_text = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)

    # Relationships
    vote = db.relationship('Vote', back_populates='options')
    casts = db.relationship('VoteCast', back_populates='option', cascade="all, delete-orphan")

    serialize_rules = (
        '-vote.options',
        '-casts.option',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'vote_id': self.vote_id,
            'option_text': self.option_text,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'vote_count': len(self.casts) if self.casts else 0
        }

class VoteCast(db.Model, SerializerMixin):
    __tablename__ = "vote_casts"

    id = db.Column(db.Integer, primary_key=True)
    vote_id = db.Column(db.Integer, db.ForeignKey('votes.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('vote_options.id'), nullable=False)
    voted_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    anonymous = db.Column(db.Boolean, default=True)

    __table_args__ = (
        db.UniqueConstraint('vote_id', 'user_id', name='unique_vote_cast'),
    )

    # Relationships
    vote = db.relationship('Vote', back_populates='casts')
    voter = db.relationship('User', back_populates='votes_cast')
    option = db.relationship('VoteOption', back_populates='casts')

    serialize_rules = (
        '-vote.casts',
        '-voter.votes_cast',
        '-option.casts',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'vote_id': self.vote_id,
            'user_id': self.user_id,
            'option_id': self.option_id,
            'voted_at': self.voted_at.isoformat() if self.voted_at else None,
            'anonymous': self.anonymous,
            'option_text': self.option.option_text if self.option else None
        }

class Feedback(db.Model, SerializerMixin):
    __tablename__ = "feedback"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.Enum('general', 'complaint', 'suggestion', 'appreciation', name='feedback_categories'), default='general')
    status = db.Column(db.Enum('new', 'read', 'addressed', 'closed', name='feedback_status'), default='new')
    response = db.Column(db.Text)
    responded_at = db.Column(db.TIMESTAMP)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    updated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    chama = db.relationship('Chama', back_populates='feedbacks')
    user = db.relationship('User', back_populates='feedbacks')

    serialize_rules = (
        '-chama.feedbacks',
        '-user.feedbacks',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'chama_id': self.chama_id,
            'user_id': self.user_id,
            'message': self.message,
            'category': self.category,
            'status': self.status,
            'response': self.response,
            'responded_at': self.responded_at.isoformat() if self.responded_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'user_name': self.user.username if self.user else None,
            'chama_name': self.chama.name if self.chama else None
        }

class Report(db.Model, SerializerMixin):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    report_type = db.Column(db.Enum('contributions', 'loans', 'members', 'financial', 'voting', name='report_types'), nullable=False)
    title = db.Column(db.Text, nullable=False)
    data = db.Column(db.JSON)
    parameters = db.Column(db.JSON)  # Store filters and parameters used
    file_path = db.Column(db.Text)  # Path to generated PDF/CSV file
    generated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    period_start = db.Column(db.TIMESTAMP)
    period_end = db.Column(db.TIMESTAMP)

    # Relationships
    chama = db.relationship('Chama', back_populates='reports')
    generated_by = db.relationship('User', back_populates='reports_generated')

    serialize_rules = (
        '-chama.reports',
        '-generated_by.reports_generated',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'chama_id': self.chama_id,
            'user_id': self.user_id,
            'report_type': self.report_type,
            'title': self.title,
            'data': self.data,
            'parameters': self.parameters,
            'file_path': self.file_path,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
            'period_start': self.period_start.isoformat() if self.period_start else None,
            'period_end': self.period_end.isoformat() if self.period_end else None,
            'generated_by_name': self.generated_by.username if self.generated_by else None,
            'chama_name': self.chama.name if self.chama else None
        }

class Notification(db.Model, SerializerMixin):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'))
    title = db.Column(db.Text, nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.Enum('info', 'warning', 'success', 'error', 'reminder', name='notification_types'), default='info')
    is_read = db.Column(db.Boolean, default=False)
    action_url = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    read_at = db.Column(db.TIMESTAMP)

    # Used back_populates instead of simple relationships
    user = db.relationship('User', back_populates='notifications')
    chama = db.relationship('Chama')

    serialize_rules = (
        '-user.notifications',
        '-chama',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'chama_id': self.chama_id,
            'title': self.title,
            'message': self.message,
            'notification_type': self.notification_type,
            'is_read': self.is_read,
            'action_url': self.action_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'chama_name': self.chama.name if self.chama else None
        }

class AuditLog(db.Model, SerializerMixin):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'))
    action = db.Column(db.Text, nullable=False)
    resource_type = db.Column(db.Text, nullable=False)
    resource_id = db.Column(db.Integer)
    details = db.Column(db.JSON)
    ip_address = db.Column(db.Text)
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)

    # Used back_populates instead of simple relationships
    user = db.relationship('User', back_populates='audit_logs')
    chama = db.relationship('Chama')

    serialize_rules = (
        '-user.audit_logs',
        '-chama',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'chama_id': self.chama_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'user_name': self.user.username if self.user else None,
            'chama_name': self.chama.name if self.chama else None
        }