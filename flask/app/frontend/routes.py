from flask import render_template
from app.frontend import frontendBp

@frontendBp.route("/login")
def login():
    return render_template('/auth/login.html')

@frontendBp.route("/register")
def register():
    return render_template('/auth/register.html')

@frontendBp.route("/")
def home():
    return render_template('/home/index.html')

@frontendBp.route("/leaderboard")
def leader():
    return render_template('/home/leaderboard.html')