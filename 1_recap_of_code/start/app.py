from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from blacklist import BLACKLIST
from resources.user import (
    UserRegister,
    User,
    UserLogin,
    TokenRefresh,
    UserLogout)
from resources.item import Item, ItemList
from resources.store import Store, StoreList

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True
# Enabling blacklist for both access and refresh tokens
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.secret_key = 'jose'  # can also use: app.config['JWT_SECRET_KEY']
api = Api(app)


@app.before_first_request
def create_tables():
    db.create_all()

# Unlike JWT, JWTManager does not creating
# the /auth enpoint, we will create this oursleves
jwt = JWTManager(app)


@jwt.user_claims_loader
def add_claims_to_jwt(identity):
    """
    This function will check if any extra data should
    be added to the JWT token
    """
    # 1 here is the first user to be created in the db
    # In a live system this should not be hard coded but, 
    # read from a config file or database
    if identity == 1:
        return {'is_admin': True}
    return {'is_admin': False}

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    """
    Retuns true if the token being sent is blacklisted
    """
    # Below 'jti' field is in the JWT and comes from
    # the flask_jwt_extended internals
    return decrypted_token['jti'] in BLACKLIST

@jwt.expired_token_loader
def expired_token_callback():
    """
    When flask_jwt_extended notes that a token sent has already 
    expired, this function will be called to find out what 
    message should be sent back to the user saying expired token
    """
    return jsonify({
        'description': 'The token has expired.',
        'error': 'token_expired'
    }), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'description': 'Signature varification failed.',
        'error': 'invalid_token'
    }), 401

# No JWT token sent
@jwt.unauthorized_loader
def missing_token_callback():
    return jsonify({
        'description': 'Request does not contain an access token.',
        'error': 'authorization_required'
    }), 401

@jwt.needs_fresh_token_loader
def token_not_fresh_callback():
    return jsonify({
        'description': 'The token is not fresh',
        'error': 'fresh_token_required'
    }), 401


# Token no longer valid
@jwt.revoked_token_loader
def revoked_token_callback():
    return jsonify({
        'description': 'The token used has been revoked',
        'error': 'token_revoked'
    }), 401

api.add_resource(Store, '/store/<string:name>')
api.add_resource(StoreList, '/stores')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(UserRegister, '/register')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogout, '/logout')
api.add_resource(UserLogin, '/login')
api.add_resource(TokenRefresh, '/refresh')


if __name__ == '__main__':
    from db import db
    db.init_app(app)
    app.run(port=5000, debug=True)
