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
    MembershipStatus,
    MembershipRole,
    PollStatus,
)


# =========================================================
# HELPERS
# =========================================================

def get_current_user():
    identity = get_jwt_identity()
    if not identity:
        return None
    return User.query.get(identity)


def audit_log(
    action,
    actor_user_id=None,
    target_user_id=None,
    chama_id=None,
    poll_id=None,
    vote_id=None,
    membership_id=None,
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
            membership_id=membership_id,
            description=description,
            old_values=old_values,
            new_values=new_values,
            metadata_json=metadata_json,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception:
        pass


def get_active_membership(user_id, chama_id):
    return Membership.query.filter_by(
        user_id=user_id,
        chama_id=chama_id,
        status=MembershipStatus.ACTIVE
    ).first()


def require_chama_membership(current_user, chama_id):
    if not current_user:
        return None, ({"message": "User not found."}, 404)

    if not current_user.is_active_account:
        return None, ({"message": "Inactive account cannot access chama resources."}, 403)

    chama = Chama.query.get(chama_id)
    if not chama:
        return None, ({"message": "Chama not found."}, 404)

    membership = get_active_membership(current_user.id, chama_id)
    if not membership:
        return None, ({"message": "Access denied. You are not a member of this chama."}, 403)

    return (chama, membership), None


def require_poll_manager(current_user, chama_id):
    result, error = require_chama_membership(current_user, chama_id)
    if error:
        return None, error

    chama, membership = result
    if membership.role not in {MembershipRole.ADMIN, MembershipRole.SECRETARY}:
        return None, ({"message": "Only admin or secretary can manage polls."}, 403)

    return (chama, membership), None


def poll_option_dict(option):
    return {
        "id": option.id,
        "poll_id": option.poll_id,
        "option_text": option.option_text,
        "created_at": option.created_at.isoformat() if option.created_at else None,
        "updated_at": option.updated_at.isoformat() if option.updated_at else None,
    }


def vote_dict(vote):
    return {
        "id": vote.id,
        "poll_id": vote.poll_id,
        "option_id": vote.option_id,
        "option_text": vote.option.option_text if vote.option else None,
        "user_id": vote.user_id,
        "user_name": vote.user.full_name if vote.user else None,
        "created_at": vote.created_at.isoformat() if vote.created_at else None,
        "updated_at": vote.updated_at.isoformat() if vote.updated_at else None,
    }


def poll_dict(poll, include_options=True, include_results=False):
    data = {
        "id": poll.id,
        "chama_id": poll.chama_id,
        "title": poll.title,
        "description": poll.description,
        "status": poll.status.value if poll.status else None,
        "created_by_user_id": poll.created_by_user_id,
        "created_by_name": poll.created_by.full_name if poll.created_by else None,
        "opens_at": poll.opens_at.isoformat() if poll.opens_at else None,
        "closes_at": poll.closes_at.isoformat() if poll.closes_at else None,
        "is_open": poll.is_open,
        "created_at": poll.created_at.isoformat() if poll.created_at else None,
        "updated_at": poll.updated_at.isoformat() if poll.updated_at else None,
    }

    if include_options:
        data["options"] = [poll_option_dict(option) for option in poll.options]

    if include_results:
        results = []
        for option in poll.options:
            vote_count = Vote.query.filter_by(poll_id=poll.id, option_id=option.id).count()
            results.append({
                "option_id": option.id,
                "option_text": option.option_text,
                "vote_count": vote_count,
            })
        data["results"] = results
        data["total_votes"] = Vote.query.filter_by(poll_id=poll.id).count()

    return data


def normalize_poll_status(value):
    if not value:
        return None
    value = value.strip().lower()
    for status in PollStatus:
        if status.value == value:
            return status
    return None


# =========================================================
# RESOURCES
# =========================================================

class ChamaPollsResource(Resource):
    """
    GET /chamas/<int:chama_id>/polls
    POST /chamas/<int:chama_id>/polls
    """
    @jwt_required()
    def get(self, chama_id):
        current_user = get_current_user()
        result, error = require_chama_membership(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        status = request.args.get("status", type=str)

        query = (
            Poll.query
            .filter(Poll.chama_id == chama.id)
            .order_by(Poll.created_at.desc(), Poll.id.desc())
        )

        if status:
            normalized_status = normalize_poll_status(status)
            if not normalized_status:
                return {"message": "Invalid poll status."}, 400
            query = query.filter(Poll.status == normalized_status)

        polls = query.all()

        return {
            "message": "Polls retrieved successfully.",
            "count": len(polls),
            "polls": [poll_dict(poll, include_options=True, include_results=False) for poll in polls]
        }, 200

    @jwt_required()
    def post(self, chama_id):
        current_user = get_current_user()
        result, error = require_poll_manager(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        data = request.get_json() or {}

        title = (data.get("title") or "").strip()
        description = data.get("description")
        options = data.get("options") or []
        opens_at_raw = data.get("opens_at")
        closes_at_raw = data.get("closes_at")
        status_raw = data.get("status") or "draft"

        if not title:
            return {"message": "title is required."}, 400

        if not isinstance(options, list) or len(options) < 2:
            return {"message": "At least 2 options are required."}, 400

        cleaned_options = []
        for option in options:
            text = str(option).strip()
            if text:
                cleaned_options.append(text)

        cleaned_options = list(dict.fromkeys(cleaned_options))
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

        if opens_at and closes_at and closes_at < opens_at:
            return {"message": "closes_at cannot be before opens_at."}, 400

        status = normalize_poll_status(status_raw)
        if not status:
            return {"message": "Invalid poll status."}, 400

        poll = Poll(
            chama_id=chama.id,
            title=title,
            description=description,
            status=status,
            created_by_user_id=current_user.id,
            opens_at=opens_at,
            closes_at=closes_at,
        )
        db.session.add(poll)
        db.session.flush()

        for option_text in cleaned_options:
            db.session.add(PollOption(
                poll_id=poll.id,
                option_text=option_text
            ))

        db.session.commit()

        audit_log(
            action=AuditAction.POLL_CREATED,
            actor_user_id=current_user.id,
            chama_id=chama.id,
            poll_id=poll.id,
            membership_id=membership.id,
            description="Poll created.",
            new_values=poll_dict(poll, include_options=True, include_results=False),
        )

        return {
            "message": "Poll created successfully.",
            "poll": poll_dict(poll, include_options=True, include_results=False)
        }, 201


class PollDetailResource(Resource):
    """
    GET /chamas/<int:chama_id>/polls/<int:poll_id>
    PATCH /chamas/<int:chama_id>/polls/<int:poll_id>
    DELETE /chamas/<int:chama_id>/polls/<int:poll_id>
    """
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
            "poll": poll_dict(poll, include_options=True, include_results=True)
        }, 200

    @jwt_required()
    def patch(self, chama_id, poll_id):
        """Only admin or secretary can update polls."""
        current_user = get_current_user()
        result, error = require_poll_manager(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        poll = Poll.query.filter_by(id=poll_id, chama_id=chama.id).first()

        if not poll:
            return {"message": "Poll not found."}, 404

        data = request.get_json() or {}
        old_values = poll_dict(poll, include_options=True, include_results=False)

        if "title" in data:
            title = (data.get("title") or "").strip()
            if not title:
                return {"message": "title cannot be empty."}, 400
            poll.title = title

        if "description" in data:
            poll.description = data.get("description")

        if "status" in data:
            status = normalize_poll_status(data.get("status"))
            if not status:
                return {"message": "Invalid poll status."}, 400
            poll.status = status

        if "opens_at" in data:
            opens_at_raw = data.get("opens_at")
            if opens_at_raw in [None, ""]:
                poll.opens_at = None
            else:
                try:
                    poll.opens_at = datetime.fromisoformat(opens_at_raw)
                except ValueError:
                    return {"message": "Invalid opens_at. Use ISO format."}, 400

        if "closes_at" in data:
            closes_at_raw = data.get("closes_at")
            if closes_at_raw in [None, ""]:
                poll.closes_at = None
            else:
                try:
                    poll.closes_at = datetime.fromisoformat(closes_at_raw)
                except ValueError:
                    return {"message": "Invalid closes_at. Use ISO format."}, 400

        if poll.opens_at and poll.closes_at and poll.closes_at < poll.opens_at:
            return {"message": "closes_at cannot be before opens_at."}, 400

        db.session.commit()

        audit_log(
            action=AuditAction.POLL_UPDATED,
            actor_user_id=current_user.id,
            chama_id=chama.id,
            poll_id=poll.id,
            membership_id=membership.id,
            description="Poll updated.",
            old_values=old_values,
            new_values=poll_dict(poll, include_options=True, include_results=False),
        )

        return {
            "message": "Poll updated successfully.",
            "poll": poll_dict(poll, include_options=True, include_results=False)
        }, 200

    @jwt_required()
    def delete(self, chama_id, poll_id):
        """Only admin or secretary can delete polls."""
        current_user = get_current_user()
        result, error = require_poll_manager(current_user, chama_id)
        if error:
            return error

        chama, membership = result
        poll = Poll.query.filter_by(id=poll_id, chama_id=chama.id).first()

        if not poll:
            return {"message": "Poll not found."}, 404

        old_values = poll_dict(poll, include_options=True, include_results=True)

        db.session.delete(poll)
        db.session.commit()

        audit_log(
            action=AuditAction.POLL_DELETED,
            actor_user_id=current_user.id,
            chama_id=chama.id,
            poll_id=poll_id,
            membership_id=membership.id,
            description="Poll deleted.",
            old_values=old_values,
            new_values=None,
            metadata_json={"deleted_poll_id": poll_id},
        )

        return {"message": "Poll deleted successfully."}, 200


class CastVoteResource(Resource):
    """
    POST /chamas/<int:chama_id>/polls/<int:poll_id>/vote
    One active member, one vote.
    """
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

        data = request.get_json() or {}
        option_id = data.get("option_id")

        if not option_id:
            return {"message": "option_id is required."}, 400

        option = PollOption.query.filter_by(id=option_id, poll_id=poll.id).first()
        if not option:
            return {"message": "Selected option does not belong to this poll."}, 400

        existing_vote = Vote.query.filter_by(
            poll_id=poll.id,
            user_id=current_user.id
        ).first()

        if existing_vote:
            return {"message": "You have already voted in this poll."}, 400

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
            membership_id=membership.id,
            description="Vote cast in poll.",
            new_values=vote_dict(vote),
        )

        return {
            "message": "Vote cast successfully.",
            "vote": vote_dict(vote)
        }, 201


class MyPollVoteResource(Resource):
    """
    GET /chamas/<int:chama_id>/polls/<int:poll_id>/my-vote
    """
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

        vote = Vote.query.filter_by(
            poll_id=poll.id,
            user_id=current_user.id
        ).first()

        return {
            "message": "My vote retrieved successfully.",
            "has_voted": vote is not None,
            "vote": vote_dict(vote) if vote else None
        }, 200


class PollVotesResource(Resource):
    """
    GET /chamas/<int:chama_id>/polls/<int:poll_id>/votes
    Active members can see votes/results.
    """
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

        votes = (
            Vote.query
            .filter_by(poll_id=poll.id)
            .order_by(Vote.created_at.asc(), Vote.id.asc())
            .all()
        )

        return {
            "message": "Poll votes retrieved successfully.",
            "poll": poll_dict(poll, include_options=True, include_results=True),
            "count": len(votes),
            "votes": [vote_dict(v) for v in votes]
        }, 200
