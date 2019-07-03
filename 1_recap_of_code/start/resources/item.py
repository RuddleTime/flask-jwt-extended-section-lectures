from flask_restful import Resource, reqparse
from flask_jwt_extended import (jwt_required, get_jwt_claims,
    jwt_optional, get_jwt_identity, fresh_jwt_required) 
from models.item import ItemModel


class Item(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('price',
                        type=float,
                        required=True,
                        help="This field cannot be left blank!"
                        )
    parser.add_argument('store_id',
                        type=int,
                        required=True,
                        help="Every item needs a store_id."
                        )

    # If using flask_jwt instead of flask_jwt_extended
    # this decorator would be @jwt_required()
    @jwt_required
    def get(self, name):
        item = ItemModel.find_by_name(name)
        if item:
            return item.json()
        return {'message': 'Item not found'}, 404

    @fresh_jwt_required
    def post(self, name):
        if ItemModel.find_by_name(name):
            return {'message': "An item with name '{}' already exists.".format(name)}, 400

        data = Item.parser.parse_args()

        item = ItemModel(name, **data)

        try:
            item.save_to_db()
        except:
            return {"message": "An error occurred inserting the item."}, 500

        return item.json(), 201

    @jwt_required
    def delete(self, name):
        claims = get_jwt_claims() # claims set up in app.py
        if not claims['is_admin']:
            return {
                'message': 'Admin permissions required for this action'
            }, 401
        item = ItemModel.find_by_name(name)
        
        if item:
            item.delete_from_db()
            return {'message': 'Item deleted.'}
        return {'message': 'Item not found.'}, 404

    def put(self, name):
        data = Item.parser.parse_args()

        item = ItemModel.find_by_name(name)

        if item:
            item.price = data['price']
        else:
            item = ItemModel(name, **data)

        item.save_to_db()

        return item.json()


class ItemList(Resource):
    @jwt_optional
    def get(self):
        # get_jwt_identity will give us whatever we saved 
        # in the access token as the identity.
        # The below will give the user ID in the user that is stored
        # in the JWT, if there is no JWT token, None is returned (meaning
        # the user is not logged in).
        user_id = get_jwt_identity()
        items = [item.json() for item in ItemModel.find_all()]
        if user_id:
            return {'items': items}, 200 
        return {
            'items': [item['name'] for item in items],
            'message': 'More data available if you log in.'
        }, 200



