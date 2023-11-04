from flask import request, jsonify
from app.extensions import db

from app.user import userBp
from app.models.user import Users

@userBp.route("", methods=['GET'], strict_slashes = False)
def get_user():
    limit = request.args.get('limit', 10)
    if type(limit) is not int:
        return jsonify({'message': 'invalid parameter'}), 400

    users = db.session.execute(
        db.select(Users).limit(limit)
    ).scalars()

    result = []
    for user in users:
        result.append(user.serialize())

    return jsonify(data=result), 200