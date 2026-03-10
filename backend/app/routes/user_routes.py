from Resources.User import (
    SignupResource,
    LoginResource,
    UsersResource,
    UserProfileResource,
    ChangePasswordResource,
    ForgotPasswordResource,
    ResetPasswordResource,
    RefreshTokenResource,
    UserDetailResource,
)


def register_user_routes(api):
    """Register all user/auth related routes."""
    api.add_resource(SignupResource, "/api/v1/auth/signup")
    api.add_resource(LoginResource, "/api/v1/auth/login")
    api.add_resource(RefreshTokenResource, "/api/v1/auth/refresh")
    api.add_resource(ChangePasswordResource, "/api/v1/auth/change-password")
    api.add_resource(ForgotPasswordResource, "/api/v1/auth/forgot-password")
    api.add_resource(ResetPasswordResource, "/api/v1/auth/reset-password")

    api.add_resource(UsersResource, "/api/v1/users")
    api.add_resource(UserProfileResource, "/api/v1/users/profile")
    api.add_resource(UserDetailResource, "/api/v1/users/<int:user_id>")