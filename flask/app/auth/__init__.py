from flask import Blueprint
from flask_cors import CORS

authBp = Blueprint('auth', __name__)
CORS(authBp,  supports_credentials=True)

from app.auth import routes