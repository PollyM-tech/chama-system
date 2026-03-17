from .chama_routes import register_chama_routes
from .contribution_routes import register_contribution_routes
from .loan_routes import register_loan_routes
from .user_routes import register_user_routes
from .vote_routes import register_vote_routes

__all__ = [
    "register_chama_routes",
    "register_contribution_routes",
    "register_loan_routes",
    "register_user_routes",
    "register_vote_routes",
]