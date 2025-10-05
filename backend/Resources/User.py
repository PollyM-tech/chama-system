from flask import request, jsonify
from flask_restful import Resource
from models import User, db
from werkzeug.security import generate_password_hash

class UsersResource(Resource):
    def get(self):
        users = User.query.all()  # ✅ variable should be lowercase 'users'
        data = [
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at.isoformat()
            }
            for user in users
        ]
        return jsonify(data)

    def post(self):
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        # ✅ Check required fields
        if not username or not email or not password:
            return {"error": "Missing required fields"}, 400

        # ✅ Check duplicate email
        if User.query.filter_by(email=email).first():
            return {"error": "Email already exists"}, 400

        # ✅ Hash password
        hashed_pw = generate_password_hash(password)

        # ✅ Create user
        new_user = User(username=username, email=email, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        return {
            "message": "User created successfully",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email
            }
        }, 201
