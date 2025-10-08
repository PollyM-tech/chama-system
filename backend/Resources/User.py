from flask import request
from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token
from werkzeug.security import check_password_hash
from models import db, User

class UsersResource(Resource):
    def get(self):
        users = User.query.all()
        return [user.to_dict() for user in users], 200
    
    def post(self):
        data = request.get_json()
        if User.query.filter_by(email=data.get("email")).first():
            return {"message": "User with this email already exists"}, 422
        
        user = User(
            username=data.get("username"),
            email=data.get("email"),
            role=data.get("role", "member")
        )
        user.set_password(data.get("password"))
        
        db.session.add(user)
        db.session.commit()
        
        return {"message": "User created successfully", "user": user.to_dict()}, 201


class SignupResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("username", required=True, help="Username is required")
    parser.add_argument("email", required=True, help="Email is required")
    parser.add_argument("password", required=True, help="Password is required")
    parser.add_argument("role", required=False, default="member")

    def post(self):
        data = self.parser.parse_args()

        if User.query.filter_by(email=data["email"]).first():
            return {"message": "User with this email already exists"}, 422

        user = User(
            username=data["username"],
            email=data["email"],
            role=data["role"]
        )
        user.set_password(data["password"])

        db.session.add(user)
        db.session.commit()

        access_token = create_access_token(identity=user.id)

        return {
            "message": "Signup successful",
            "user": user.to_dict(),
            "access_token": access_token
        }, 201


class LoginResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("email", required=True, help="Email is required")
    parser.add_argument("password", required=True, help="Password is required")

    def post(self):
        data = self.parser.parse_args()
        user = User.query.filter_by(email=data["email"]).first()

        if not user or not user.check_password(data["password"]):
            return {"message": "Invalid email or password"}, 401

        access_token = create_access_token(identity=user.id)
        return {
            "message": "Login successful",
            "access_token": access_token,
            "user": user.to_dict()
        }, 200
