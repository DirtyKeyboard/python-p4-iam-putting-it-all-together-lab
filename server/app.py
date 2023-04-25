#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        username = request.get_json()['username']
        password = request.get_json()['password']
        password_confirmation = request.get_json()['password_confirmation']
        image_url = request.get_json()['image_url']
        bio = request.get_json()['bio']

        if password!= password_confirmation:
            return {'message': 'Passwords do not match'}, 400
        
        user = User(username=username, image_url=image_url, bio=bio)
        user.password_hash = password
        db.session.add(user)
        try:
            db.session.commit()
            session['user_id'] = user.id
            return {'message': 'User created'}, 201
        except IntegrityError:
            return {'message': 'User already exists'}, 409
class CheckSession(Resource):
    def get(self):
        if 'user_id' not in session:
            return {'message': 'Not logged in'}, 401
        
        uid = session['user_id']
        current_user = User.query.filter(User.id == uid).first()
        return (current_user.to_dict(), 200)

class Login(Resource):
    def post(self):
        username = request.get_json()['username']
        password = request.get_json()['password']

        user = User.query.filter(User.username == username).first()
        if not user or not user.authenticate(password):
            return ({'message': 'Invalid username or password'}, 401)

        session['user_id'] = user.id
        return (user.to_dict(), 200)

class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return {'message': 'Logged out'}, 200

class RecipeIndex(Resource):
    def get(self):
        if session['user_id']:
            recipes = Recipe.query.filter(Recipe.user_id == session['user_id']).all()
            return ([recipe.to_dict() for recipe in recipes], 200)
        else:
            return {'message': 'Not logged in'}, 401
    
    def post(self):
        title = request.get_json()['title']
        instructions = request.get_json()['instructions']
        minutes_to_complete = request.get_json()['minutes_to_complete']

        recipe = Recipe(title=title, instructions=instructions, minutes_to_complete=minutes_to_complete, user_id=session['user_id'])
        
        if not session['user_id']:
            return {'message': 'Not logged in'}, 401
        
        try:
            db.session.add(recipe)
            db.session.commit()
            return {'message': 'Recipe created'}, 201
        except IntegrityError:
            return {'message': 'Recipe already exists'}, 409


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
