from flask import Blueprint
from flask_cors import CORS

countBp = Blueprint('countBp', __name__)
CORS(countBp)

from app.postCount import routes