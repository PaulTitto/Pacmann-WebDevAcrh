from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager # ditambah
from flask_login import LoginManager

db = ()
migrate = Migrate()
jwt = JWTManager()
login_manager = LoginManager()