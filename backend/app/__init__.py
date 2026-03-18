from flask import Flask
from flask_restful import Api
from flask_cors import CORS
from dotenv import load_dotenv

from app.config import Config
from app.extensions import db, migrate, jwt, mail
from app.routes import (
    register_user_routes,
    register_chama_routes,
    register_loan_routes,
    register_contribution_routes,
    register_vote_routes,
)


def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    mail.init_app(app)

    CORS(app, resources={r"/api/*": {"origins": app.config["FRONTEND_URL"]}})

    register_user_routes(app)
    register_chama_routes(app)
    register_loan_routes(app)
    register_contribution_routes(app)
    register_vote_routes(app)

    @app.route("/")
    def index():
        return {"message": "Welcome to Smart Chama"}, 200

    return app