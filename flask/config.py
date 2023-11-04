import os
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta # ditambah

basedir = os.path.abspath(os.path.dirname(__file__))
DB_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

class Config:
    SECRET_KEY = '123'
    SQLALCHEMY_DATABASE_URI = DB_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ditambah
    JWT_TOKEN_LOCATION = ["headers", "cookies"]
    JWT_SECRET_KEY = "super-secret"
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    