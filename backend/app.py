from flask_cors import CORS
from dotenv import load_dotenv
import os
from flask_migrate import Migrate
from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from models import db

from Resources.User import UsersResource


load_dotenv()
app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")


db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)
api.add_resource(UsersResource, '/users')




if __name__ == '__main__':
    app.run(port=5555, debug=True)