from flask import Blueprint
from flask_cors import CORS

tweetBp = Blueprint('tweet', __name__)
CORS(tweetBp)
from app.tweet import routes