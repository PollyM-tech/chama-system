from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from dotenv import load_dotenv
import os
from datetime import timedelta

from models import db
from Resources.User import (
    SignupResource, LoginResource, UsersResource, UserProfileResource, 
    ChangePasswordResource, ForgotPasswordResource, ResetPasswordResource, 
    RefreshTokenResource, UserDetailResource
)
from Resources.Chama import ChamasResource, ChamaDetailResource, MembershipResource
from Resources.Loan import LoansResource, LoanCalculatorResource, LoanManagementResource
from Resources.Contribution import ContributionsResource, ChamaContributionsResource, ContributionSummaryResource
from Resources.Vote import VotesResource, VoteCastResource

load_dotenv()
app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT Configuration
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER", os.getenv("MAIL_USERNAME"))

# Frontend URL for email links
app.config['FRONTEND_URL'] = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
mail = Mail(app)
CORS(app)

api = Api(app)

# Authentication routes
api.add_resource(SignupResource, '/signup')
api.add_resource(LoginResource, '/login')
api.add_resource(RefreshTokenResource, '/refresh-token')
api.add_resource(ChangePasswordResource, '/change-password')
api.add_resource(ForgotPasswordResource, '/forgot-password')
api.add_resource(ResetPasswordResource, '/reset-password')

# User routes
api.add_resource(UsersResource, '/users')
api.add_resource(UserProfileResource, '/profile')
api.add_resource(UserDetailResource, '/users/<int:user_id>')

# Chama routes
api.add_resource(ChamasResource, '/chamas')
api.add_resource(ChamaDetailResource, '/chamas/<int:chama_id>')
api.add_resource(MembershipResource, '/chamas/<int:chama_id>/members')

# Loan routes
api.add_resource(LoansResource, '/loans')
api.add_resource(LoanCalculatorResource, '/loans/calculator')
api.add_resource(LoanManagementResource, '/chamas/<int:chama_id>/loans')
api.add_resource(LoanManagementResource, '/chamas/<int:chama_id>/loans/<int:loan_id>', 
                 endpoint='loan_management')

# Contribution routes
api.add_resource(ContributionsResource, '/contributions')
api.add_resource(ChamaContributionsResource, '/chamas/<int:chama_id>/contributions')
api.add_resource(ContributionSummaryResource, '/chamas/<int:chama_id>/contributions/summary')

# Vote routes
api.add_resource(VotesResource, '/chamas/<int:chama_id>/votes')
api.add_resource(VoteCastResource, '/votes/<int:vote_id>/cast')

@app.route("/")
def index():
    return {"message": "Welcome to Chama Management API"}, 200

if __name__ == '__main__':
    app.run(port=5555, debug=True)