from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Vote, VoteOption, VoteCast, Membership
from schemas import vote_schema, votes_schema, vote_option_schema, vote_options_schema
from marshmallow import ValidationError
from datetime import datetime

class VotesResource(Resource):
    @jwt_required()
    def post(self, chama_id):
        current_user_id = get_jwt_identity()
        
        # Check if user is admin of the chama
        admin_membership = Membership.query.filter_by(
            user_id=current_user_id,
            chama_id=chama_id,
            role__in=['chairperson', 'treasurer']
        ).first()
        
        if not admin_membership:
            return {"message": "Only admins can create votes"}, 403

        try:
            data = request.get_json()
            topic = data.get('topic')
            description = data.get('description')
            options = data.get('options', [])
            closed_at = data.get('closed_at')

            if not topic:
                return {"message": "Topic is required"}, 400
            if len(options) < 2:
                return {"message": "At least 2 options are required"}, 400

            # Parse closed_at date
            if closed_at:
                try:
                    closed_at = datetime.fromisoformat(closed_at.replace('Z', '+00:00'))
                except ValueError:
                    return {"message": "Invalid closed_at format. Use ISO format"}, 400

            vote = Vote(
                chama_id=chama_id,
                created_by=current_user_id,
                topic=topic,
                description=description,
                closed_at=closed_at,
                status='open'
            )

            db.session.add(vote)
            db.session.flush()  # Get vote ID

            # Create vote options
            for option_text in options:
                option = VoteOption(
                    vote_id=vote.id,
                    option_text=option_text
                )
                db.session.add(option)

            db.session.commit()

            return {
                "message": "Vote created successfully",
                "vote": vote_schema.dump(vote)
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": str(e)}, 500

    @jwt_required()
    def get(self, chama_id):
        user_id = get_jwt_identity()
        
        # Check if user is member of the chama
        membership = Membership.query.filter_by(
            user_id=user_id,
            chama_id=chama_id
        ).first()
        
        if not membership:
            return {"message": "Not a member of this chama"}, 403

        status = request.args.get('status', 'open')
        
        votes = Vote.query.filter_by(chama_id=chama_id, status=status).all()
        
        votes_data = []
        for vote in votes:
            vote_data = vote_schema.dump(vote)
            
            # Get options
            options = VoteOption.query.filter_by(vote_id=vote.id).all()
            vote_data['options'] = vote_options_schema.dump(options)
            
            # Check if user has voted
            user_vote = VoteCast.query.filter_by(
                vote_id=vote.id,
                user_id=user_id
            ).first()
            vote_data['has_voted'] = user_vote is not None
            
            # If vote is closed or user is admin, show results
            if vote.status == 'closed' or membership.role in ['chairperson', 'treasurer']:
                vote_data['results'] = self.get_vote_results(vote.id)
            
            votes_data.append(vote_data)

        return votes_data, 200

    def get_vote_results(self, vote_id):
        # Get vote counts per option
        results = db.session.query(
            VoteOption.option_text,
            db.func.count(VoteCast.id).label('count')
        ).join(
            VoteCast, VoteCast.option_id == VoteOption.id
        ).filter(
            VoteOption.vote_id == vote_id
        ).group_by(
            VoteOption.id, VoteOption.option_text
        ).all()

        total_votes = sum(result.count for result in results)
        
        return {
            'total_votes': total_votes,
            'options': [
                {
                    'option_text': result.option_text,
                    'votes': result.count,
                    'percentage': round((result.count / total_votes) * 100, 2) if total_votes > 0 else 0
                }
                for result in results
            ]
        }

class VoteCastResource(Resource):
    @jwt_required()
    def post(self, vote_id):
        user_id = get_jwt_identity()
        
        try:
            data = request.get_json()
            option_id = data.get('option_id')

            if not option_id:
                return {"message": "Option ID is required"}, 400

            # Check if vote exists and is open
            vote = Vote.query.get(vote_id)
            if not vote:
                return {"message": "Vote not found"}, 404

            if vote.status != 'open':
                return {"message": "Voting is closed for this poll"}, 400

            # Check if user is member of the chama
            membership = Membership.query.filter_by(
                user_id=user_id,
                chama_id=vote.chama_id,
                status='active'
            ).first()
            
            if not membership:
                return {"message": "Not an active member of this chama"}, 403

            # Check if user has already voted
            existing_vote = VoteCast.query.filter_by(
                vote_id=vote_id,
                user_id=user_id
            ).first()
            
            if existing_vote:
                return {"message": "You have already voted in this poll"}, 422

            # Check if option exists for this vote
            option = VoteOption.query.filter_by(
                id=option_id,
                vote_id=vote_id
            ).first()
            
            if not option:
                return {"message": "Invalid option"}, 400

            vote_cast = VoteCast(
                vote_id=vote_id,
                user_id=user_id,
                option_id=option_id
            )

            db.session.add(vote_cast)
            db.session.commit()

            return {
                "message": "Vote cast successfully",
                "vote_cast": {
                    "vote_id": vote_id,
                    "option_id": option_id
                }
            }, 201

        except Exception as e:
            return {"message": str(e)}, 500