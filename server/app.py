#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        
        # Extracting data
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        # Validate input
        if not username or not password:
            return {'error': 'Username and password must be provided'}, 422

        # Create a new user
        new_user = User(username=username, image_url=image_url, bio=bio)
        new_user.password = password  # Using the setter to hash the password
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Store the user_id in session
            session['user_id'] = new_user.id

            return {
                'message': 'User created successfully',
                'id': new_user.id,
                'username': new_user.username,
                'image_url': new_user.image_url,
                'bio': new_user.bio
            }, 201
        
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already exists'}, 409  # Conflict error

        except Exception as e:
            db.session.rollback()
            return {'error': 'Failed to create user'}, 422  # Log exception details


class CheckSession(Resource):
    def get(self):
        if 'user_id' in session:
            user = db.session.get(User, session['user_id'])
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }, 200
        
        return {'error': 'Unauthorized'}, 401
            

class Login(Resource):
    def post(self):
        data = request.get_json()
        
        # Extracting data
        username = data.get('username')
        password = data.get('password')
        
        # Validate the input
        if not username or not password:
            return {'error': 'Invalid username or password'}, 401
        
        # Find the user in the database
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Store the user_id in the session
            session['user_id'] = user.id
            return {
                'user_id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200
        
        return {'error': 'Invalid username or password'}, 401  # Unauthorized


class Logout(Resource):
    def delete(self):
        if 'user_id' in session and session['user_id'] is not None:
            del session['user_id']
            return '', 204  # No content
        else:
            return {'error': 'Unauthorized'}, 401  # Not authorized


class RecipeIndex(Resource):
    def get(self):
        # Check if the user is logged in
        if 'user_id' in session and session['user_id'] is not None:
            recipes = Recipe.query.filter_by(user_id=session['user_id']).all()
            recipes_data = []

            for recipe in recipes:
                recipe_info = {
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': {
                        'id': recipe.user.id,
                        'username': recipe.user.username,
                        'image_url': recipe.user.image_url,
                        'bio': recipe.user.bio
                    }
                }
                recipes_data.append(recipe_info)

            return {'recipes': recipes_data}, 200
        
        return {'error': 'Unauthorized'}, 401

    def post(self):
        # Check if the user is logged in
        if 'user_id' in session and session['user_id'] is not None:
            data = request.get_json()

            # Extract the data
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            # Validate the data
            if not title or not instructions or minutes_to_complete is None:
                return {'error': 'Invalid data'}, 422  # Return 422 for validation errors

            # Fetch the user within the session context
            user = db.session.get(User, session['user_id'])
            if user is None:
                return {'error': 'User not found'}, 404  # Handle user not found

            # Create a new recipe
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user=user  # Directly use the user object
            )

            # Add the new recipe to the database
            db.session.add(new_recipe)

            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                return {'error': 'Failed to create recipe'}, 422  # Handle integrity errors

            # Create a dictionary for the new recipe
            new_recipe_data = {
                'title': new_recipe.title,
                'instructions': new_recipe.instructions,
                'minutes_to_complete': new_recipe.minutes_to_complete,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }
            }

            return new_recipe_data, 201  # Return created recipe with a 201 status
        else:
            return {'error': 'Not authorized'}, 401  # Return 401 if not logged in


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
