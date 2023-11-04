from flask import request, jsonify, make_response
from app.extensions import db

from app.tweet import tweetBp
from app.models.tweet import Tweets
from app.models.user import Users

from flask_jwt_extended import jwt_required, get_jwt_identity
from minio import Minio
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os


from sqlalchemy import desc

#Setup Minio
UPLOAD_FOLDER = "./static"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
BUCKET_NAME = "twitterclone"

client = Minio(
        "play.min.io", 
        access_key="Q3AM3UQ867SPQQA43P2F",
        secret_key="zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG",
    )

def allowed_file(filename):
    filename = filename.lower()
    ekstension = filename.split('.')[-1]
    return ekstension in ALLOWED_EXTENSIONS

@tweetBp.route("", methods=['GET'], strict_slashes = False)
@jwt_required(locations=["headers"],optional=True)
def get_tweet():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 2, type=int)
    if type(per_page) is not int:
        return jsonify({'message': 'invalid parameter'}), 400
    
    user_id = get_jwt_identity()

    if not user_id:
        user_id = "None"
    else:
        user_id = user_id

    # get tweets by id
    tweets = Tweets.query.order_by(desc(Tweets.id)).paginate(page=page, per_page=per_page)

    results = []
    for tweet in tweets:
        results.append(tweet.serialize())

    response = make_response(jsonify(
        user_id = user_id,
        data=results,
        page=tweets.page,
        total_page=tweets.pages,
        total_item=tweets.total
    ), 200)
    
    return response


@tweetBp.route("", methods=['POST'], strict_slashes = False)
@jwt_required(locations=["headers"])
def post_tweet():

    #buat sebuah bucket bernama imageBucket
    found = client.bucket_exists(BUCKET_NAME)
    if not found:
        client.make_bucket(BUCKET_NAME)
    else:
        print(f"Bucket {BUCKET_NAME} already exists")

    # Cek jika file di upload
    if 'file' in request.files:
        file = request.files['file']
        # Jika file ada dan sesuai format yang diizinkan

        # Waktu expire link gambar dari minio
        expiration_time = timedelta(days=7)

        if file and allowed_file(file.filename):
            # mendapatkan request json dari client
            content = request.form.get('content')
            user_id = get_jwt_identity()
            image_name = secure_filename(file.filename)
            image_size = os.fstat(file.fileno()).st_size
            client.put_object(BUCKET_NAME, image_name, file , image_size)
            image_path = client.presigned_get_object(BUCKET_NAME, image_name, expires=expiration_time)
            # menambahkan content baru
            new_content = Tweets(content = content,
                                image_name = image_name,
                                image_path = image_path,
                                user_id = user_id)    
            # menambahkan data ke database
            db.session.add(new_content)
            db.session.commit()
            # membuat response
            response = jsonify(
                success = True,
                data = new_content.serialize()
            )     
            return response, 200
    
    data = request.get_json()
    content = data.get('content', None)
    
    if not content:
        return jsonify({'error': 'Invalid data'}), 422
    
    user_id = get_jwt_identity()

    tweet = Tweets(
        user_id = user_id,
        content=content
    )
    db.session.add(tweet)
    db.session.commit()

    # make response
    response = make_response(jsonify(data=tweet.serialize()), 200)
    return response
