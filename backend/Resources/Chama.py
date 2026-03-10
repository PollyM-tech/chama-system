from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, Chama, Membership
from schemas import chama_schema, chamas_schema, membership_schema, memberships_schema
from marshmallow import ValidationError

class ChamasResource(Resource):
    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        
        try:
            data = chama_schema.load(request.get_json())
        except ValidationError as err:
            return {"errors": err.messages}, 400

        if Chama.query.filter_by(name=data.name).first():
            return {"message": "Chama with this name already exists"}, 422

        chama = Chama(name=data.name, description=data.description)
        db.session.add(chama)
        db.session.flush()  # Get the chama ID without committing

        membership = Membership(
            user_id=user_id,
            chama_id=chama.id,
            role="chairperson",
            status="active"
        )

        db.session.add(membership)
        db.session.commit()

        return {
            "message": "Chama created successfully",
            "chama": chama_schema.dump(chama),
            "membership": membership_schema.dump(membership)
        }, 201

    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        memberships = Membership.query.filter_by(user_id=user_id).all()

        chamas_data = []
        for membership in memberships:
            chama_data = chama_schema.dump(membership.chama)
            chama_data.update({
                "membership_role": membership.role,
                "membership_status": membership.status,
                "joined_at": membership.joined_at.isoformat() if membership.joined_at else None
            })
            chamas_data.append(chama_data)

        return chamas_data, 200

class ChamaDetailResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        user_id = get_jwt_identity()
        
        # Check if user is member of this chama
        membership = Membership.query.filter_by(
            user_id=user_id, 
            chama_id=chama_id
        ).first()
        
        if not membership:
            return {"message": "Not a member of this chama"}, 403

        chama = Chama.query.get(chama_id)
        if not chama:
            return {"message": "Chama not found"}, 404

        # Get members
        members = Membership.query.filter_by(chama_id=chama_id).all()
        members_data = []
        for member in members:
            member_data = {
                "user_id": member.user_id,
                "username": member.user.username,
                "email": member.user.email,
                "role": member.role,
                "status": member.status,
                "joined_at": member.joined_at.isoformat() if member.joined_at else None
            }
            members_data.append(member_data)

        chama_data = chama_schema.dump(chama)
        chama_data['members'] = members_data
        chama_data['user_role'] = membership.role

        return chama_data, 200

class MembershipResource(Resource):
    @jwt_required()
    def post(self, chama_id):
        current_user_id = get_jwt_identity()
        
        # Check if current user is admin of the chama
        admin_membership = Membership.query.filter_by(
            user_id=current_user_id,
            chama_id=chama_id,
            role__in=['chairperson', 'treasurer']
        ).first()
        
        if not admin_membership:
            return {"message": "Only admins can add members"}, 403

        try:
            data = request.get_json()
            user_email = data.get('email')
            role = data.get('role', 'member')
            
            if not user_email:
                return {"message": "User email is required"}, 400

            # Finding user by email
            user = User.query.filter_by(email=user_email).first()
            if not user:
                return {"message": "User not found"}, 404

            # Check if already a member
            existing_membership = Membership.query.filter_by(
                user_id=user.id,
                chama_id=chama_id
            ).first()
            
            if existing_membership:
                return {"message": "User is already a member of this chama"}, 422

            membership = Membership(
                user_id=user.id,
                chama_id=chama_id,
                role=role,
                status='active'
            )

            db.session.add(membership)
            db.session.commit()

            return {
                "message": "Member added successfully",
                "membership": membership_schema.dump(membership)
            }, 201

        except Exception as e:
            return {"message": str(e)}, 500