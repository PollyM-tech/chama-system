from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, Chama, Membership

class ChamasResource(Resource):
    @jwt_required()
    def post(self):
        # Get logged-in user
        user_id = get_jwt_identity()
        data = request.get_json()

        name = data.get("name")
        description = data.get("description")

        if not name:
            return {"message": "Chama name is required"}, 400

        if Chama.query.filter_by(name=name).first():
            return {"message": "Chama with this name already exists"}, 422

        # Create chama
        chama = Chama(name=name, description=description)

        # Assign creator as chairperson
        membership = Membership(
            user_id=user_id,
            chama_id=chama.id,
            role="chairperson",
            status="active"
        )

        db.session.add_all([chama, membership])
        db.session.commit()

        return {
            "message": "Chama created successfully",
            "chama": {
                "id": chama.id,
                "name": chama.name,
                "description": chama.description,
            },
            "membership": {
                "user_id": user_id,
                "role": membership.role,
                "status": membership.status,
            }
        }, 201

    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        memberships = Membership.query.filter_by(user_id=user_id).all()

        data = [
            {
                "chama_id": m.chama.id,
                "chama_name": m.chama.name,
                "role": m.role,
                "status": m.status,
            }
            for m in memberships
        ]
        return data, 200
