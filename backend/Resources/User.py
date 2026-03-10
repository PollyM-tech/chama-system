import secrets
import string
from datetime import datetime, timedelta
from flask import request, url_for, current_app
from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, create_refresh_token
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from models import db, User, Profile, PasswordResetToken, AuditLog
from schemas import user_schema, users_schema, profile_schema
from flask_mail import Message
from marshmallow import ValidationError
import re
import logging

# Set up logging
logger = logging.getLogger(__name__)

class SignupResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("full_name", required=True, help="Full name is required")
    parser.add_argument("email", required=True, help="Email is required")
    parser.add_argument("password", required=True, help="Password is required")
    parser.add_argument("phone", required=False)
    parser.add_argument("remember_me", type=bool, default=False)

    def post(self):
        data = self.parser.parse_args()

        # Validate email
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data["email"]):
            return {"message": "Invalid email format"}, 400

        # Validate password
        password_errors = self._validate_password(data["password"])
        if password_errors:
            return {"message": "Password does not meet requirements", "errors": password_errors}, 400

        # Check if user exists
        if User.query.filter_by(email=data["email"]).first():
            return {"message": "Email address is already registered"}, 422

        # Hash password
        hashed_password = generate_password_hash(data["password"])

        # Generate username
        username = data["email"].split("@")[0]
        counter = 1
        original_username = username
        while User.query.filter_by(username=username).first():
            username = f"{original_username}{counter}"
            counter += 1

        # Create user instance
        user = User(
            username=username,
            email=data["email"],
            password=hashed_password,
            role="member"
        )

        try:
            # Save user and profile
            db.session.add(user)
            db.session.flush()  # Get user.id

            # Split full name
            name_parts = data["full_name"].strip().split(" ", 1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ""

            profile = Profile(
                user_id=user.id,
                first_name=first_name,
                last_name=last_name,
                phone=data.get("phone")
            )
            db.session.add(profile)

            # Create audit log
            audit_log = AuditLog(
                user_id=user.id,
                action="user_registered",
                resource_type="user",
                resource_id=user.id,
                details={"email": data["email"], "username": username}
            )
            db.session.add(audit_log)

            db.session.commit()

            # Send welcome email
            try:
                from app import mail  # Import your Flask-Mail instance
                welcome_msg = Message(
                    subject="Welcome to Smart Chama!",
                    recipients=[user.email],
                    body=f"Hello {first_name},\n\n"
                         "Thank you for registering at Smart Chama! "
                         "We're excited to have you on board.\n\n"
                         "Best regards,\nSmart Chama Team"
                )
                mail.send(welcome_msg)
                logger.info(f"Welcome email sent to {user.email}")
            except Exception as e:
                logger.error(f"Failed to send welcome email to {user.email}: {str(e)}")

            # Create JWT tokens
            expires_delta = timedelta(days=30) if data["remember_me"] else timedelta(hours=24)
            access_token = create_access_token(identity=user.id, expires_delta=expires_delta)
            refresh_token = create_refresh_token(identity=user.id)

            logger.info(f"New user registered: {user.email} (ID: {user.id})")

            return {
                "message": "Account created successfully",
                "user": user_schema.dump(user),
                "access_token": access_token,
                "refresh_token": refresh_token
            }, 201

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during user registration: {str(e)}")
            return {"message": "An error occurred during registration. Please try again."}, 500


    def _validate_password(self, password):
        """Validate password strength"""
        errors = []
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", password):
            errors.append("Password must contain at least one number")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character")
        return errors

class LoginResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("email", required=True, type=str, help="Email address is required")
    parser.add_argument("password", required=True, type=str, help="Password is required")
    parser.add_argument("remember_me", type=bool, default=False)

    def post(self):
        data = self.parser.parse_args()

        # 1. Check if user with email is present
        user = User.query.filter_by(email=data["email"]).first()

        if user is None:
            logger.warning(f"Failed login attempt for non-existent email: {data['email']}")
            return {"message": "Incorrect email address or password"}, 401

        # Check if user is active
        if not user.is_active:
            logger.warning(f"Login attempt for deactivated account: {user.email}")
            return {"message": "Account is deactivated. Please contact administrator."}, 401

        # 2. Verify password
        if check_password_hash(user.password, data["password"]):
            # Create tokens with remember_me consideration
            expires_delta = timedelta(days=30) if data["remember_me"] else timedelta(hours=24)
            access_token = create_access_token(
                identity=user.id, 
                expires_delta=expires_delta
            )
            refresh_token = create_refresh_token(identity=user.id)

            # Update last login time (you might want to add this field to User model)
            user.last_login = datetime.utcnow()
            
            # Create audit log
            audit_log = AuditLog(
                user_id=user.id,
                action="user_logged_in",
                resource_type="user",
                resource_id=user.id
            )
            db.session.add(audit_log)
            db.session.commit()

            logger.info(f"User logged in: {user.email} (ID: {user.id})")

            return {
                "message": "Login successful",
                "user": user_schema.dump(user),
                "access_token": access_token,
                "refresh_token": refresh_token
            }, 200
        else:
            logger.warning(f"Failed login attempt for user: {user.email}")
            return {"message": "Incorrect email or password"}, 401

class RefreshTokenResource(Resource):
    @jwt_required(refresh=True)
    def post(self):
        try:
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or not user.is_active:
                return {"message": "Invalid refresh token"}, 401

            access_token = create_access_token(identity=current_user_id)
            
            logger.info(f"Token refreshed for user ID: {current_user_id}")
            
            return {
                "access_token": access_token
            }, 200
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return {"message": "Invalid refresh token"}, 401

class UsersResource(Resource):
    @jwt_required()
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if not current_user:
            return {"message": "User not found"}, 404
            
        # Only allow admins to see all users
        if current_user.role not in ['chairperson', 'treasurer']:
            return {"message": "Unauthorized - Admin access required"}, 403
            
        users = User.query.filter_by(is_active=True).all()
        return users_schema.dump(users), 200

class UserProfileResource(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return {"message": "User not found"}, 404
            
        profile_data = profile_schema.dump(user.profile) if user.profile else {}
        
        return {
            "user": user_schema.dump(user),
            "profile": profile_data
        }, 200

    @jwt_required()
    def put(self):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return {"message": "User not found"}, 404

        try:
            profile_data = profile_schema.load(request.get_json(), partial=True)
        except ValidationError as err:
            return {"errors": err.messages}, 400

        # Update profile
        if not user.profile:
            profile = Profile(user_id=user.id, **profile_data)
            db.session.add(profile)
        else:
            for key, value in profile_data.items():
                setattr(user.profile, key, value)

        # Create audit log
        audit_log = AuditLog(
            user_id=user_id,
            action="profile_updated",
            resource_type="profile",
            resource_id=user.profile.id if user.profile else None
        )
        db.session.add(audit_log)
        db.session.commit()

        logger.info(f"Profile updated for user ID: {user_id}")

        return {
            "message": "Profile updated successfully",
            "profile": profile_schema.dump(user.profile)
        }, 200

class ChangePasswordResource(Resource):
    @jwt_required()
    def put(self):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("current_password", required=True)
        parser.add_argument("new_password", required=True)
        data = parser.parse_args()

        if not check_password_hash(user.password, data["current_password"]):
            return {"message": "Current password is incorrect"}, 401

        errors = validate_password(data["new_password"])
        if errors:
            return {"message": "New password does not meet requirements", "errors": errors}, 400

        if check_password_hash(user.password, data["new_password"]):
            return {"message": "New password cannot be the same as current password"}, 400

        user.set_password(data["new_password"])
        db.session.add(AuditLog(user_id=user_id, action="password_changed", resource_type="user", resource_id=user.id))
        db.session.commit()
        return {"message": "Password updated successfully"}, 200

class ForgotPasswordResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("email", required=True)

    def post(self):
        data = self.parser.parse_args()
        user = User.query.filter_by(email=data["email"], is_active=True).first()
        if user:
            try:
                token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
                PasswordResetToken.query.filter_by(user_id=user.id).delete()
                reset_record = PasswordResetToken(user_id=user.id, token=token, expires_at=datetime.utcnow() + timedelta(hours=1))
                db.session.add(reset_record)
                db.session.add(AuditLog(user_id=user.id, action="password_reset_requested", resource_type="user", resource_id=user.id))
                db.session.commit()

                # Send email
                reset_link = f"{current_app.config.get('FRONTEND_URL','http://localhost:5173')}/reset-password?token={token}"
                try:
                    msg = Message(subject="Reset Your Password", recipients=[user.email],
                                  body=f"Click here to reset your password: {reset_link}")
                    current_app.mail.send(msg)
                except Exception as e:
                    logger.error(f"Error sending password reset email: {str(e)}")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error generating reset token for {user.email}: {str(e)}")
        return {"message": "You will receive a password reset link shortly."}, 200

class ResetPasswordResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("token", required=True)
    parser.add_argument("new_password", required=True)

    def post(self):
        data = self.parser.parse_args()
        reset_record = PasswordResetToken.query.filter_by(token=data["token"], used=False).first()
        if not reset_record or reset_record.expires_at < datetime.utcnow():
            return {"message": "Invalid or expired reset token"}, 400

        user = User.query.get(reset_record.user_id)
        if not user or not user.is_active:
            return {"message": "Invalid reset token"}, 400

        errors = validate_password(data["new_password"])
        if errors:
            return {"message": "New password does not meet requirements", "errors": errors}, 400

        user.set_password(data["new_password"])
        reset_record.used = True
        reset_record.used_at = datetime.utcnow()
        db.session.add(AuditLog(user_id=user.id, action="password_reset_completed", resource_type="user", resource_id=user.id))
        db.session.commit()

        return {"message": "Password reset successfully"}, 200

class UserDetailResource(Resource):
    @jwt_required()
    def get(self, user_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        # Users can view their own profile, admins can view any profile
        if current_user_id != user_id and current_user.role not in ['chairperson', 'treasurer']:
            return {"message": "Unauthorized"}, 403

        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        profile_data = profile_schema.dump(user.profile) if user.profile else {}
        
        return {
            "user": user_schema.dump(user),
            "profile": profile_data
        }, 200

    @jwt_required()
    def delete(self, user_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        # Only admins or the user themselves can deactivate accounts
        if current_user_id != user_id and current_user.role not in ['chairperson', 'treasurer']:
            return {"message": "Unauthorized"}, 403

        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        # Prevent self-deactivation for admins
        if current_user_id == user_id and current_user.role in ['chairperson', 'treasurer']:
            # Check if there are other admins in the user's chamas
            admin_count = self._get_admin_count(user_id)
            if admin_count <= 1:
                return {"message": "You cannot deactivate account. You are the only admin in one or more chamas."}, 400

        # Soft delete by setting is_active to False
        user.is_active = False
        
        # Create audit log
        audit_log = AuditLog(
            user_id=current_user_id,
            action="user_deactivated",
            resource_type="user",
            resource_id=user_id,
            details={"deactivated_by": current_user_id}
        )
        db.session.add(audit_log)
        db.session.commit()

        logger.info(f"User account deactivated: {user.email} (ID: {user_id}) by user ID: {current_user_id}")

        return {"message": "User account deactivated successfully"}, 200

    def _get_admin_count(self, user_id):
        """Count how many admin roles the user has across chamas"""
        from models import Membership
        admin_memberships = Membership.query.filter_by(
            user_id=user_id,
            role__in=['chairperson', 'treasurer']
        ).count()
        return admin_memberships