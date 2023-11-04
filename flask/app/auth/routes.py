from sqlalchemy.exc import IntegrityError
from flask import request, jsonify, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token, create_refresh_token, jwt_required, get_jwt, get_jwt_identity

from app.extensions import db, jwt
from app.auth import authBp
from app.models.user import Users
from app.models.blacklist_token import BlacklistToken

from flask_login import login_user

@authBp.route("/register", methods=['POST'], strict_slashes =False)
def registration():
    # get data from request json
    data = request.get_json()
    print(data)
    # get username password email from json
    username = data.get('username', None)
    password = generate_password_hash(data.get('password', None))
    email = data.get('email', None)
    role = data.get('role', None)
    error = None

    if not username or not password or not email:
        return jsonify({"message": "Username, password, and email are required."}), 400
    
    try:
        db.session.add(Users(username=username,
                                password=password,
                                email=email, role=role))
        db.session.commit()
    except IntegrityError:
        return jsonify({
            "error": "User already Exist",}), 400       


    response = make_response(jsonify({
        "success": True,
        "message":"Berhasil Mendaftarkan User",
        }), 200)
    
    # response.headers['Access-Control-Allow-Origin'] = '*'
    # response.headers['Content_Type'] = 'application/json'
    # jika berhasil berikan message berhasil login
    return response

@authBp.route("/login", methods=['POST'], strict_slashes = False)
def login():
    # get data from request json
    data = request.get_json()
    
    # get username password from json
    username = data.get('username', None)
    password = data.get('password', None)

    # validasi input
    if not username:
        error = 'Username is required.'
    elif not password:
        error = 'Password is required.'
    
    error = None
    # query record user dari database dengan username request
    user = Users.query.filter_by(username=username).first()

    # cek apakah user ada
    if user is None:
        error = "username not found"
        return jsonify({"error": error}), 422
    elif not check_password_hash(user.password, password):
        error = "Incorrect password"
        return jsonify({"error": error}), 422
    # ditambahkan
    else:
        login_user(user)
        access_token = create_access_token(identity=user.user_id)
        refresh_token = create_refresh_token(identity=user.user_id)       
    
    # make response
    response = make_response(jsonify({
        "success": True,
        "message":"Berhasil Login",
        "access_token" : access_token,
        "refresh_token": refresh_token}), 200)
    # response.headers['Access-Control-Allow-Origin'] = '*'
    # jika berhasil berikan message berhasil login
    return response

@authBp.route('/refresh', methods=['POST'], strict_slashes = False)
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    access_token = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(access_token), 200

@authBp.route("/logout", methods=['POST'], strict_slashes = False)
@jwt_required(locations=["headers"])
def logout():
    # mendapatkan token jwt
    raw_jwt = get_jwt()

    # menambahkan token jwt ke blacklist
    # mencabut JWT dan menolak akses ke permintaan di masa mendatang
    jti = raw_jwt.get('jti')
    token = BlacklistToken(jti = jti)
    
    db.session.add(token)
    db.session.commit()

    # make response
    response = make_response(jsonify(
        {
        "message":"Berhasil Logout",
        "success": True}), 200)
    return response

# callback untuk memeriksa apakah JWT ada di daftar blokir atau tidak
@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_redis = BlacklistToken.query.filter_by(jti=jti).first()
    return token_in_redis is not None