from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Contribution, Membership, Chama
from schemas import contribution_schema, contributions_schema
from marshmallow import ValidationError
from datetime import datetime

class ContributionsResource(Resource):
    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        
        try:
            data = contribution_schema.load(request.get_json())
        except ValidationError as err:
            return {"errors": err.messages}, 400

        # Check if user is active member of the chama
        membership = Membership.query.filter_by(
            user_id=user_id, 
            chama_id=data.chama_id,
            status='active'
        ).first()
        
        if not membership:
            return {"message": "Not an active member of this chama"}, 403

        contribution = Contribution(
            chama_id=data.chama_id,
            user_id=user_id,
            amount=data.amount,
            payment_method=data.payment_method,
            reference=data.get('reference', ''),
            status='confirmed'
        )

        db.session.add(contribution)
        db.session.commit()

        return {
            "message": "Contribution recorded successfully",
            "contribution": contribution_schema.dump(contribution)
        }, 201

    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        
        chama_id = request.args.get('chama_id')
        month = request.args.get('month')
        year = request.args.get('year')
        
        query = Contribution.query.filter_by(user_id=user_id)
        
        if chama_id:
            query = query.filter_by(chama_id=chama_id)
            
        contributions = query.order_by(Contribution.contribution_date.desc()).all()
        return contributions_schema.dump(contributions), 200

class ChamaContributionsResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user_id = get_jwt_identity()
        
        # Check if user is member of the chama
        membership = Membership.query.filter_by(
            user_id=current_user_id,
            chama_id=chama_id
        ).first()
        
        if not membership:
            return {"message": "Not a member of this chama"}, 403

        # Check if user is admin for detailed report
        is_admin = membership.role in ['chairperson', 'treasurer']
        
        if is_admin:
            # Admin can see all contributions
            contributions = Contribution.query.filter_by(chama_id=chama_id).all()
        else:
            # Regular members can only see their own contributions
            contributions = Contribution.query.filter_by(
                chama_id=chama_id, 
                user_id=current_user_id
            ).all()

        contributions_data = []
        total_contributions = 0
        
        for contribution in contributions:
            contribution_data = contribution_schema.dump(contribution)
            contribution_data['user_name'] = contribution.user.username
            contributions_data.append(contribution_data)
            total_contributions += contribution.amount

        return {
            "contributions": contributions_data,
            "total_contributions": total_contributions,
            "member_count": len(set(c.user_id for c in contributions)),
            "is_admin": is_admin
        }, 200

class ContributionSummaryResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user_id = get_jwt_identity()
        
        # Check if user is admin of the chama
        admin_membership = Membership.query.filter_by(
            user_id=current_user_id,
            chama_id=chama_id,
            role__in=['chairperson', 'treasurer']
        ).first()
        
        if not admin_membership:
            return {"message": "Only admins can view contribution summary"}, 403

        # Get summary data
        total_contributions = db.session.query(
            db.func.sum(Contribution.amount)
        ).filter_by(
            chama_id=chama_id,
            status='confirmed'
        ).scalar() or 0

        member_count = Membership.query.filter_by(
            chama_id=chama_id,
            status='active'
        ).count()

        # Get monthly breakdown
        monthly_data = db.session.query(
            db.func.strftime('%Y-%m', Contribution.contribution_date).label('month'),
            db.func.sum(Contribution.amount).label('total')
        ).filter_by(
            chama_id=chama_id,
            status='confirmed'
        ).group_by('month').order_by('month').all()

        monthly_breakdown = [
            {'month': data.month, 'total': float(data.total or 0)}
            for data in monthly_data
        ]

        return {
            "total_contributions": float(total_contributions),
            "active_members": member_count,
            "average_per_member": float(total_contributions / member_count) if member_count > 0 else 0,
            "monthly_breakdown": monthly_breakdown
        }, 200