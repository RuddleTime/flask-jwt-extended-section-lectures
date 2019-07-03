from flask_restful import Resource, reqparse
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    jwt_refresh_token_required,
    get_jwt_identity,
    get_raw_jwt
    )
from models.user import UserModel
from blacklist import BLACKLIST

_user_parser = reqparse.RequestParser()
_user_parser.add_argument('username',
                    type=str,
                    required=True,
                    help="This field cannot be blank."
                    )
_user_parser.add_argument('password',
                    type=str,
                    required=True,
                    help="This field cannot be blank."
                    )


class UserRegister(Resource):

    def post(self):
        data = _user_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message": "A user with that username already exists"}, 400

        user = UserModel(**data)
        user.save_to_db()

        return {"message": "User created successfully."}, 201


# Creating new resource to retrieve user details and delete users
class User(Resource):
    
    # Both of the below are class methods due
    # to not needing to access self
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        return user.json()

    @classmethod
    def delete(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        user.delete_from_db()
        return {'message': 'User deleted'}, 200


class UserLogin(Resource):
    
    @classmethod
    def post(cls):
        """
        Actions covered by this method:
        1. get data from _user_parser
        2. find user in database
        3. check password
        4. create access token
        5. create refresh token 
        6. return info
        """
       
        # Getting data from _user_parser
        data = _user_parser.parse_args()

        # Find user in db
        user = UserModel.find_by_username(data['username']) 

        # Checking password
        if user and safe_str_cmp(user.password, data['password']):
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200

        return {'message': 'Invalid credentials'}, 401
    

class UserLogout(Resource):
    @jwt_required
    def post(self):
        # Want to blacklist the jwt that the user has sent us
        
        # Get unique identifier for the access token, which
        # they all have (nothing to do with the particular user)
        # jti = jwt identifier
        jti = get_raw_jwt()['jti']
        BLACKLIST.add(jti)
        return {'message': 'Successfully logged out.'}, 200


class TokenRefresh(Resource):

    @jwt_refresh_token_required
    def post(self):
        """
        Must already have a refresh token to get in here
        """
        # Refresh token can be used to get the user identity
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token': new_token}, 200

