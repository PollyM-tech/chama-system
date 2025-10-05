from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
import os
from flask_migrate import Migrate
from flask import Flask
from flask_restful import Api
from flask_mail import Mail
from models import db


load_dotenv()
app = Flask(__name__)
CORS(app)

