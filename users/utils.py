from flask import current_app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from users.models import User


def get_reset_token(user, expires_sec=1800):
    serializer = Serializer(current_app.config['SECRET_KEY'], expires_sec)
    return serializer.dumps({'user_id': user.id}).decode('utf-8')


def verify_reset_token(token):
    serializer = Serializer(current_app.config['SECRET_KEY'])
    try:
        user_id = serializer.loads(token)['user_id']
    except (KeyError, Exception):
        return None
    return User.query.get(user_id)
