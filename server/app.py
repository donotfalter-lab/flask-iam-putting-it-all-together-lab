#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

user_schema = UserSchema(exclude=('recipes',))
recipe_schema = RecipeSchema()
recipes_schema = RecipeSchema(many=True)

class Signup(Resource):
    def post(self):
        json = request.get_json() or {}

        user = User(
            username=json.get('username'),
            image_url=json.get('image_url'),
            bio=json.get('bio'),
        )

        password = json.get('password')
        if password:
            user.password_hash = password

        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['Username is required and must be unique.']}, 422

        session['user_id'] = user.id
        return user_schema.dump(user), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = db.session.get(User, user_id)
            if user:
                return user_schema.dump(user), 200
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        json = request.get_json() or {}
        username = json.get('username')
        password = json.get('password') or ''

        user = User.query.filter(User.username == username).first()
        if user and user._password_hash and user.authenticate(password):
            session['user_id'] = user.id
            return user_schema.dump(user), 200

        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id', None)
            return {}, 204
        return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        return recipes_schema.dump(Recipe.query.all()), 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        json = request.get_json() or {}
        try:
            recipe = Recipe(
                title=json.get('title'),
                instructions=json.get('instructions'),
                minutes_to_complete=json.get('minutes_to_complete'),
                user_id=user_id,
            )
            db.session.add(recipe)
            db.session.commit()
        except (IntegrityError, ValueError) as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        return recipe_schema.dump(recipe), 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
