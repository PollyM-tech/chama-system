from datetime import datetime

from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import (
    db,
    User,
    Chama,
    Membership,
    Poll,
    PollOption,
    Vote,
    AuditLog,
    AuditAction,
    MembershipRole,
    MembershipStatus,
    PollStatus,
)


# =========================================================
# HELPERS
# =========================================================

def get_current_user():
    identity = get_jwt_identity()
    if not identity:
        return None

    try:
        user_id = int(identity)
    except (ValueError, TypeError):
        return None

    return User.query.get(user_id)


def get_chama_by_id(chama_id):
    return Chama.query.get(chama_id)


def get_active_membership(user_id, chama_id):
    return Membership.query.filter_by(
        user_id=user_id,
        chama_id=chama_id,
        status=MembershipStatus.ACTIVE,
    ).first()


def require_chama_membership(current_user, chama_id):
    if not current_user:
        return None, ({"message": "User not found."}, 404)

    if not current_user.is_active_account:
        return None, ({"message": "Inactive account cannot access chama resources."}, 403)

    chama = get_chama_by_id(chama_id)
    if not chama:
        return None, ({"message": "Chama not found."}, 404)

    membership = get_active_membership(current_user.id, chama_id)
    if not membership:
        return None, ({"message": "Access denied. You are not an active member of this chama."}, 403)

    return (chama, membership), None


def require_poll_manager_roles(current_user, chama_id):
    result, error = require_chama_membership(current_user, chama_id)
    if error:
        return None, error

    chama, membership = result

    if membership.role not in {MembershipRole.ADMIN, MembershipRole.SECRETARY}:
        return None, ({"message": "Only admin or secretary can manage polls."}, 403)

    return (chama, membership), None


def audit_log(
    action,
    actor_user_id=None,
    target_user_id=None,
    chama_id=None,
    poll_id=None,
    vote_id=None,
    description=None,
    old_values=None,
    new_values=None,
    metadata_json=None,
):
    try:
        AuditLog.log(
            action=action,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            chama_id=chama_id,
            poll_id=poll_id,
            vote_id=vote_id,
            description=description,
            old_values=old_values,
            new_values=new_values,
            metadata_json=metadata_json,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception:
        pass


def option_dict(option, include_vote_count=False):
    data = {
        "id": option.id,
        "poll_id": option.poll_id,
        "option_text": option.option_text,
        "created_at": option.created_at.isoformat() if option.created_at else None,
        "updated_at": option.updated_at.isoformat() if option.updated_at else None,
    }

    if include_vote_count:
        data["vote_count"] = Vote.query.filter_by(option_id=option.id).count()

    return data


def vote_dict(vote):
    return {
        "id": vote.id,
        "poll_id": vote.poll_id,
        "option_id": vote.option_id,
        "user_id": vote.user_id,
        "option_text": vote.option.option_text if vote.option else None,
        "voter_name": vote.user.full_name if vote.user else None,
        "created_at": vote.created_at.isoformat() if vote.created_at else None,
        "updated_at": vote.updated_at.isoformat() if vote.updated_at else None,
    }


def poll_dict(poll, include_options=False, include_results=False, current_user_id=None):
    data = {
        "id": poll.id,
        "chama_id": poll.chama_id,
        "title": poll.title,
        "description": poll.description,
        "status": poll.status.value if poll.status else None,
        "is_open": poll.is_open,
        "created_by_user_id": poll.created_by_user_id,
        "created_by_name": poll.created_by.full_name if poll.created_by else None,
        "opens_at": poll.opens_at.isoformat() if poll.opens_at else None,
        "closes_at": poll.closes_at.isoformat() if poll.closes_at else None,
        "created_at": poll.created_at.isoformat() if poll.created_at else None,
        "updated_at": poll.updated_at.isoformat() if poll.updated_at else None,
    }

    if current_user_id is not None:
        existing_vote = Vote.query.filter_by(poll_id=poll.id, user_id=current_user_id).first()
        data["has_voted"] = existing_vote is not None
        data["my_vote"] = vote_dict(existing_vote) if existing_vote else None

    if include_options:
        data["options"] = [option_dict(option, include_vote_count=include_results) for option in poll.options]

    if include_results:
        data["total_votes"] = Vote.query.filter_by(poll_id=poll.id).count()

    return data


# =========================================================
# RESOURCES
# =========================================================

class ChamaPollsResource(Resource):
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result

        status = request.args.get("status", type=str)

        query = Poll.query.filter_by(chama_id=chama.id)

        if status:
            status = status.strip().lower()
            matched = None
            for s in PollStatus:
                if s.value == status:
                    matched = s
                    break
            if not matched:
                return {"message": "Invalid poll status."}, 400
            query = query.filter(Poll.status == matched)

        polls = query.order_by(Poll.created_at.desc(), Poll.id.desc()).all()

        return {
            "message": "Polls retrieved successfully.",
            "count": len(polls),
            "polls": [poll_dict(p, include_options=True, include_results=True, current_user_id=current_user.id) for p in polls],
        }, 200

    @jwt_required()
    def post(self, chama_id):
        current_user = get_current_user()
        result, error = require_poll_manager_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        data = request.get_json() or {}

        title = (data.get("title") or "").strip()
        description = data.get("description")
        options = data.get("options") or []
        opens_at_raw = data.get("opens_at")
        closes_at_raw = data.get("closes_at")

        if not title:
            return {"message": "title is required."}, 400

        if not isinstance(options, list) or len(options) < 2:
            return {"message": "At least 2 options are required."}, 400

        cleaned_options = []
        seen = set()
        for item in options:
            text = str(item).strip()
            if not text:
                continue
            lowered = text.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            cleaned_options.append(text)

        if len(cleaned_options) < 2:
            return {"message": "At least 2 unique non-empty options are required."}, 400

        opens_at = None
        closes_at = None

        if opens_at_raw:
            try:
                opens_at = datetime.fromisoformat(opens_at_raw)
            except ValueError:
                return {"message": "Invalid opens_at. Use ISO format."}, 400

        if closes_at_raw:
            try:
                closes_at = datetime.fromisoformat(closes_at_raw)
            except ValueError:
                return {"message": "Invalid closes_at. Use ISO format."}, 400

        if opens_at and closes_at and closes_at <= opens_at:
            return {"message": "closes_at must be later than opens_at."}, 400

        try:
            poll = Poll(
                chama_id=chama.id,
                title=title,
                description=description,
                status=PollStatus.DRAFT,
                created_by_user_id=current_user.id,
                opens_at=opens_at,
                closes_at=closes_at,
            )
            db.session.add(poll)
            db.session.flush()

            for text in cleaned_options:
                db.session.add(PollOption(poll_id=poll.id, option_text=text))

            db.session.commit()

            audit_log(
                action=AuditAction.POLL_CREATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                poll_id=poll.id,
                description="Poll created.",
                new_values=poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id),
            )

            return {
                "message": "Poll created successfully.",
                "poll": poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error creating poll: {str(e)}"}, 500


class PollDetailResource(Resource):
    @jwt_required()
    def get(self, chama_id, poll_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        poll = Poll.query.filter_by(id=poll_id, chama_id=chama.id).first()

        if not poll:
            return {"message": "Poll not found."}, 404

        return {
            "message": "Poll retrieved successfully.",
            "poll": poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id),
        }, 200

    @jwt_required()
    def delete(self, chama_id, poll_id):
        current_user = get_current_user()
        result, error = require_poll_manager_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        poll = Poll.query.filter_by(id=poll_id, chama_id=chama.id).first()

        if not poll:
            return {"message": "Poll not found."}, 404

        if poll.status != PollStatus.DRAFT:
            return {"message": "Only draft polls can be deleted."}, 400

        old_values = poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id)

        try:
            db.session.delete(poll)
            db.session.commit()

            audit_log(
                action=AuditAction.POLL_DELETED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                poll_id=poll_id,
                description="Draft poll deleted.",
                old_values=old_values,
                new_values=None,
            )

            return {"message": "Poll deleted successfully."}, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error deleting poll: {str(e)}"}, 500


class PollOpenResource(Resource):
    @jwt_required()
    def patch(self, chama_id, poll_id):
        current_user = get_current_user()
        result, error = require_poll_manager_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        poll = Poll.query.filter_by(id=poll_id, chama_id=chama.id).first()

        if not poll:
            return {"message": "Poll not found."}, 404

        if poll.status != PollStatus.DRAFT:
            return {"message": "Only draft polls can be opened."}, 400

        if len(poll.options) < 2:
            return {"message": "Poll must have at least 2 options before opening."}, 400

        old_values = poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id)

        poll.status = PollStatus.OPEN
        if poll.opens_at is None:
            poll.opens_at = datetime.utcnow()

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.POLL_UPDATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                poll_id=poll.id,
                description="Poll opened.",
                old_values=old_values,
                new_values=poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id),
            )

            return {
                "message": "Poll opened successfully.",
                "poll": poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error opening poll: {str(e)}"}, 500


class PollCloseResource(Resource):
    @jwt_required()
    def patch(self, chama_id, poll_id):
        current_user = get_current_user()
        result, error = require_poll_manager_roles(current_user, chama_id)
        if error:
            return error

        chama, actor_membership = result
        poll = Poll.query.filter_by(id=poll_id, chama_id=chama.id).first()

        if not poll:
            return {"message": "Poll not found."}, 404

        if poll.status != PollStatus.OPEN:
            return {"message": "Only open polls can be closed."}, 400

        old_values = poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id)

        poll.status = PollStatus.CLOSED
        if poll.closes_at is None or poll.closes_at > datetime.utcnow():
            poll.closes_at = datetime.utcnow()

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.POLL_UPDATED,
                actor_user_id=current_user.id,
                chama_id=chama.id,
                poll_id=poll.id,
                description="Poll closed.",
                old_values=old_values,
                new_values=poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id),
            )

            return {
                "message": "Poll closed successfully.",
                "poll": poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error closing poll: {str(e)}"}, 500


class PollVoteResource(Resource):
    @jwt_required()
    def post(self, chama_id, poll_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        poll = Poll.query.filter_by(id=poll_id, chama_id=chama.id).first()

        if not poll:
            return {"message": "Poll not found."}, 404

        if not poll.is_open:
            return {"message": "This poll is not open for voting."}, 400

        existing_vote = Vote.query.filter_by(poll_id=poll.id, user_id=current_user.id).first()
        if existing_vote:
            return {"message": "You have already voted in this poll."}, 400

        data = request.get_json() or {}
        option_id = data.get("option_id")

        if not option_id:
            return {"message": "option_id is required."}, 400

        option = PollOption.query.filter_by(id=option_id, poll_id=poll.id).first()
        if not option:
            return {"message": "Selected option does not belong to this poll."}, 400

        try:
            vote = Vote(
                poll_id=poll.id,
                option_id=option.id,
                user_id=current_user.id,
            )
            db.session.add(vote)
            db.session.commit()

            audit_log(
                action=AuditAction.VOTE_CAST,
                actor_user_id=current_user.id,
                target_user_id=current_user.id,
                chama_id=chama.id,
                poll_id=poll.id,
                vote_id=vote.id,
                description="Vote cast successfully.",
                new_values=vote_dict(vote),
            )

            return {
                "message": "Vote cast successfully.",
                "vote": vote_dict(vote),
                "poll": poll_dict(poll, include_options=True, include_results=True, current_user_id=current_user.id),
            }, 201

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error casting vote: {str(e)}"}, 500