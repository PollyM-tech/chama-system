from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import MetaData
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy_serializer import SerializerMixin

metadata = MetaData(naming_convention={
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
})

db = SQLAlchemy(metadata=metadata)


class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text)
    email = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.Text, default="member")
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)

    profile = db.relationship('Profile', back_populates='user', uselist=False)
    memberships = db.relationship('Membership', backref='user', lazy=True)
    contributions = db.relationship('Contribution', backref='user', lazy=True)
    loans = db.relationship('Loan', backref='user', lazy=True)
    repayments = db.relationship('Repayment', backref='user', lazy=True)
    votes_created = db.relationship('Vote', backref='creator', lazy=True)
    votes_cast = db.relationship('VoteCast', backref='voter', lazy=True)
    feedbacks = db.relationship('Feedback', backref='user', lazy=True)
    reports = db.relationship('Report', backref='user', lazy=True)

    serialize_rules = (
        '-password',
        '-memberships',
        '-contributions',
        '-loans',
        '-repayments',
        '-votes_created',
        '-votes_cast',
        '-feedbacks',
        '-reports',
    )

    def set_password(self, plain_password):
        self.password = generate_password_hash(plain_password)

    def check_password(self, plain_password):
        return check_password_hash(self.password, plain_password)


class Profile(db.Model, SerializerMixin):
    __tablename__ = "profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    first_name = db.Column(db.Text)
    last_name = db.Column(db.Text)
    phone = db.Column(db.Text)
    address = db.Column(db.Text)
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.Text)
    role = db.Column(db.Text)
    bio = db.Column(db.Text)

    user = db.relationship('User', back_populates='profile')

    serialize_rules = ('-user',)


class Chama(db.Model):
    __tablename__ = "chamas"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False, unique=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)

    memberships = db.relationship('Membership', backref='chama', lazy=True)
    contributions = db.relationship('Contribution', backref='chama', lazy=True)
    loans = db.relationship('Loan', backref='chama', lazy=True)
    votes = db.relationship('Vote', backref='chama', lazy=True)
    feedbacks = db.relationship('Feedback', backref='chama', lazy=True)
    reports = db.relationship('Report', backref='chama', lazy=True)


class Membership(db.Model):
    __tablename__ = "memberships"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    role = db.Column(
        db.Enum('chairperson', 'treasurer', 'member', name='member_role'),
        nullable=False,
        default='member'
    )
    joined_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    status = db.Column(
        db.Enum('active', 'inactive', 'pending', name='member_status'),
        default='active'
    )

    __table_args__ = (
        db.UniqueConstraint('user_id', 'chama_id', name='unique_membership'),
    )

    serialize_rules = ('-user', '-chama',)



class Contribution(db.Model):
    __tablename__ = "contributions"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    contribution_date = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    payment_method = db.Column(db.Text)
    reference = db.Column(db.Text)
    status = db.Column(db.Text, default="confirmed")
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)


class Loan(db.Model):
    __tablename__ = "loans"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float)
    status = db.Column(db.Text, default="requested")
    requested_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    approved_at = db.Column(db.TIMESTAMP)
    due_date = db.Column(db.DateTime)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)


class Repayment(db.Model):
    __tablename__ = "repayments"

    id = db.Column(db.Integer, primary_key=True)
    loan_id = db.Column(db.Integer, db.ForeignKey('loans.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    amount_paid = db.Column(db.Float, nullable=False)
    payment_date = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    payment_method = db.Column(db.Text)
    reference = db.Column(db.Text)
    status = db.Column(db.Text, default="confirmed")
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)


class Vote(db.Model):
    __tablename__ = "votes"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    topic = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.Text, default="open")
    closed_at = db.Column(db.TIMESTAMP)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)


class VoteOption(db.Model):
    __tablename__ = "vote_options"

    id = db.Column(db.Integer, primary_key=True)
    vote_id = db.Column(db.Integer, db.ForeignKey('votes.id'), nullable=False)
    option_text = db.Column(db.Text, nullable=False)


class VoteCast(db.Model):
    __tablename__ = "vote_casts"

    id = db.Column(db.Integer, primary_key=True)
    vote_id = db.Column(db.Integer, db.ForeignKey('votes.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('vote_options.id'), nullable=False)
    voted_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('vote_id', 'user_id', name='unique_vote_cast'),
    )


class Feedback(db.Model):
    __tablename__ = "feedback"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    chama_id = db.Column(db.Integer, db.ForeignKey('chamas.id'), nullable=False)
    report_type = db.Column(db.Text)
    data = db.Column(db.JSON)
    generated_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
