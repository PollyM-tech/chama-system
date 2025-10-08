from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os

from models import db
from Resources.User import UsersResource, SignupResource, LoginResource
from Resources.Chama import ChamasResource

load_dotenv()
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY", "supersecret")

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
CORS(app)

api = Api(app)

api.add_resource(SignupResource, '/signup')
api.add_resource(LoginResource, '/login')
api.add_resource(UsersResource, '/users')
api.add_resource(ChamasResource, '/chamas')

@app.route("/")
def index():
    return {"message": "Welcome to Chama Management API"}, 200

if __name__ == '__main__':
    app.run(port=5555, debug=True)
