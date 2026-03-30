from flask import request
from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity

from models import (
    db,
    User,
    Notification,
    NotificationType,
    AuditLog,
    AuditAction,
)


def get_current_user():
    identity = get_jwt_identity()
    if not identity:
        return None

    try:
        user_id = int(identity)
    except (ValueError, TypeError):
        return None

    return User.query.get(user_id)


def notification_dict(notification):
    return notification.to_dict()


def audit_log(
    action,
    actor_user_id=None,
    target_user_id=None,
    description=None,
    old_values=None,
    new_values=None,
):
    try:
        AuditLog.log(
            action=action,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            description=description,
            old_values=old_values,
            new_values=new_values,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception:
        pass

def create_notification(
    user_id,
    title,
    message,
    notification_type=NotificationType.INFO,
    chama_id=None,
    action_url=None,
    metadata_json=None,
):
    notification = Notification(
        user_id=user_id,
        chama_id=chama_id,
        title=title,
        message=message,
        type=notification_type,
        action_url=action_url,
        metadata_json=metadata_json,
    )
    db.session.add(notification)
    return notification

class MyNotificationsResource(Resource):
    @jwt_required()
    def get(self):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        is_read = request.args.get("is_read")
        notification_type = request.args.get("type")

        query = Notification.query.filter_by(user_id=current_user.id)

        if is_read is not None:
            if is_read.lower() == "true":
                query = query.filter(Notification.is_read.is_(True))
            elif is_read.lower() == "false":
                query = query.filter(Notification.is_read.is_(False))

        if notification_type:
            normalized = notification_type.strip().lower()
            matched_type = None
            for item in NotificationType:
                if item.value == normalized:
                    matched_type = item
                    break
            if not matched_type:
                return {"message": "Invalid notification type."}, 400
            query = query.filter(Notification.type == matched_type)

        notifications = query.order_by(Notification.created_at.desc()).all()

        unread_count = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()

        return {
            "message": "Notifications retrieved successfully.",
            "count": len(notifications),
            "unread_count": unread_count,
            "notifications": [notification_dict(n) for n in notifications],
        }, 200


class NotificationDetailResource(Resource):
    @jwt_required()
    def get(self, notification_id):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=current_user.id
        ).first()

        if not notification:
            return {"message": "Notification not found."}, 404

        return {
            "message": "Notification retrieved successfully.",
            "notification": notification_dict(notification),
        }, 200

    @jwt_required()
    def delete(self, notification_id):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=current_user.id
        ).first()

        if not notification:
            return {"message": "Notification not found."}, 404

        old_values = notification_dict(notification)

        try:
            db.session.delete(notification)
            db.session.commit()

            audit_log(
                action=AuditAction.NOTIFICATION_DELETED,
                actor_user_id=current_user.id,
                target_user_id=current_user.id,
                description="User deleted notification.",
                old_values=old_values,
                new_values=None,
            )

            return {"message": "Notification deleted successfully."}, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error deleting notification: {str(e)}"}, 500


class NotificationMarkReadResource(Resource):
    @jwt_required()
    def patch(self, notification_id):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=current_user.id
        ).first()

        if not notification:
            return {"message": "Notification not found."}, 404

        if notification.is_read:
            return {
                "message": "Notification already marked as read.",
                "notification": notification_dict(notification),
            }, 200

        old_values = notification_dict(notification)
        notification.mark_as_read()

        try:
            db.session.commit()

            audit_log(
                action=AuditAction.NOTIFICATION_READ,
                actor_user_id=current_user.id,
                target_user_id=current_user.id,
                description="User marked notification as read.",
                old_values=old_values,
                new_values=notification_dict(notification),
            )

            return {
                "message": "Notification marked as read successfully.",
                "notification": notification_dict(notification),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error marking notification as read: {str(e)}"}, 500


class NotificationMarkAllReadResource(Resource):
    @jwt_required()
    def patch(self):
        current_user = get_current_user()
        if not current_user:
            return {"message": "User not found."}, 404

        notifications = Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).all()

        try:
            for notification in notifications:
                notification.mark_as_read()

            db.session.commit()

            return {
                "message": "All notifications marked as read successfully.",
                "updated_count": len(notifications),
            }, 200

        except Exception as e:
            db.session.rollback()
            return {"message": f"Error marking all notifications as read: {str(e)}"}, 500
        
