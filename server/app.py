#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    # endpoints that don't require a session
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401


class Signup(Resource):
    def post(self):
        request_json = request.get_json()
        try:
            user = User(
                username=request_json.get('username'),
                image_url=request_json.get('image_url'),
                bio=request_json.get('bio')
            )
            # The model setter handles bcrypt
            user.password_hash = request_json.get('password')

            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id
            return user.to_dict(), 201

        except (IntegrityError, ValueError):
            return {'error': '422 Unprocessable Entity'}, 422

class CheckSession(Resource):
    def get(self):
        # Use .get() to avoid a KeyError if no one is logged in
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            if user:
                return user.to_dict(), 200
        
        return {'error': '401 Unauthorized'}, 401


class Login(Resource):
    def post(self):
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        return {'error': '401 Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        # The instructions asked for ALL recipes with nested user data
        recipes = Recipe.query.all()
        return [recipe.to_dict() for recipe in recipes], 200
        
    def post(self):
        request_json = request.get_json()
        try:
            recipe = Recipe(
                title=request_json.get('title'),
                instructions=request_json.get('instructions'),
                minutes_to_complete=request_json.get('minutes_to_complete'),
                user_id=session.get('user_id'),
            )

            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201

        except (IntegrityError, ValueError):
            return {'error': '422 Unprocessable Entity'}, 422

# Endpoints
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)