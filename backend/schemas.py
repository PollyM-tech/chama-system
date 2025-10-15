from marshmallow import Schema, fields, ValidationError, validates, validates_schema
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, auto_field
from models import db, User, Chama, Membership, Loan, Contribution, Vote, VoteOption, VoteCast, Profile
import re
from datetime import datetime

class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True
        exclude = ('password',)
        include_relationships = True
    
    email = fields.Email(required=True)
    password = fields.Str(required=True, load_only=True)
    role = fields.Str(validate=lambda x: x in ['member', 'treasurer', 'chairperson'])

    @validates('password')
    def validate_password(self, value):
        if len(value) < 6:
            raise ValidationError('Password must be at least 6 characters')
        if not any(char.isdigit() for char in value):
            raise ValidationError('Password must contain at least one number')

    @validates('username')
    def validate_username(self, value):
        if len(value) < 3:
            raise ValidationError('Username must be at least 3 characters')
        if not re.match("^[A-Za-z0-9_]+$", value):
            raise ValidationError('Username can only contain letters, numbers and underscores')

class ProfileSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Profile
        load_instance = True
    
    date_of_birth = fields.Date()
    phone = fields.Str(validate=lambda x: len(x) >= 10 if x else True)

class ChamaSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Chama
        load_instance = True
    
    name = fields.Str(required=True, validate=lambda x: len(x) >= 3)
    description = fields.Str()

class MembershipSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Membership
        load_instance = True
    
    role = fields.Str(validate=lambda x: x in ['chairperson', 'treasurer', 'member'])
    status = fields.Str(validate=lambda x: x in ['active', 'inactive', 'pending'])

class LoanSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Loan
        load_instance = True
        exclude = ('created_at', 'approved_at')
    
    amount = fields.Float(required=True, validate=lambda x: x > 0)
    interest_rate = fields.Float(validate=lambda x: x >= 0)
    status = fields.Str(validate=lambda x: x in ['requested', 'approved', 'rejected', 'active', 'completed', 'defaulted'])

    @validates_schema
    def validate_due_date(self, data, **kwargs):
        if data.get('due_date') and data['due_date'] <= datetime.utcnow():
            raise ValidationError('Due date must be in the future')

class ContributionSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Contribution
        load_instance = True
    
    amount = fields.Float(required=True, validate=lambda x: x > 0)
    payment_method = fields.Str(validate=lambda x: x in ['mpesa', 'bank', 'other'])
    status = fields.Str(validate=lambda x: x in ['pending', 'confirmed', 'failed'])

class VoteSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Vote
        load_instance = True
    
    topic = fields.Str(required=True, validate=lambda x: len(x) >= 5)
    status = fields.Str(validate=lambda x: x in ['open', 'closed'])

class VoteOptionSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = VoteOption
        load_instance = True
    
    option_text = fields.Str(required=True, validate=lambda x: len(x) >= 1)

class VoteCastSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = VoteCast
        load_instance = True

class SignupSchema(Schema):
    full_name = fields.Str(required=True, validate=lambda x: len(x) >= 2)
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=lambda x: len(x) >= 6)
    remember_me = fields.Bool(missing=False)

class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)
    remember_me = fields.Bool(missing=False)

class ChangePasswordSchema(Schema):
    current_password = fields.Str(required=True)
    new_password = fields.Str(required=True, validate=lambda x: len(x) >= 6)

class LoanCalculatorSchema(Schema):
    amount = fields.Float(required=True, validate=lambda x: x > 0)
    interest_rate = fields.Float(required=True, validate=lambda x: x >= 0)
    term_months = fields.Int(required=True, validate=lambda x: x > 0)

# Initialize schemas
user_schema = UserSchema()
users_schema = UserSchema(many=True)
profile_schema = ProfileSchema()
chama_schema = ChamaSchema()
chamas_schema = ChamaSchema(many=True)
membership_schema = MembershipSchema()
memberships_schema = MembershipSchema(many=True)
loan_schema = LoanSchema()
loans_schema = LoanSchema(many=True)
contribution_schema = ContributionSchema()
contributions_schema = ContributionSchema(many=True)
vote_schema = VoteSchema()
votes_schema = VoteSchema(many=True)
vote_option_schema = VoteOptionSchema()
vote_options_schema = VoteOptionSchema(many=True)
vote_cast_schema = VoteCastSchema()
login_schema = LoginSchema()
loan_calculator_schema = LoanCalculatorSchema()
signup_schema = SignupSchema()
change_password_schema = ChangePasswordSchema()