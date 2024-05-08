from flask import request, session, jsonify
from flask_restful import Resource
from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
        session.clear()
        return {}, 204

class Signup(Resource):
    
    def post(self):
        json_data = request.get_json()
        username = json_data.get('username')
        password = json_data.get('password')

        if not username or not password:
            return {'message': 'Username and password are required'}, 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {'message': 'Username already exists'}, 400

        user = User(username=username)
        user.password_hash = password  # Assigning password directly without hashing for simplicity
        db.session.add(user)
        db.session.commit()

        # print(user.id)
        # user.id = 0
        # print(user.id)
        return {'username': user.username, 'user_id': user.id}, 201  # Return the username and user ID

class CheckSession(Resource):
    
    def get(self):
        if 'user_id' in session:
            user_id = session['user_id']
            user = User.query.get(user_id)
            if user:
                return {'username': user.username}, 200  # Return username if user is found
            else:
                session.clear()  # Clear session if user is not found
                return {}, 204
        else:
            return {}, 204

class Login(Resource):

    def post(self):
        json_data = request.get_json()
        username = json_data.get('username')
        password = json_data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):  # Using authenticate method to check password
            session['user_id'] = user.id
            print(user.id)
            user.id = 0
            print(user.id)
            print(user.username)
            return {'username': user.username}, 200  # Return username upon successful login
        else:
            return {'message': 'Invalid username or password'}, 401


class Logout(Resource):

    def delete(self):
        print("Logging out user...")
        session.clear()
        print("Session cleared.")
        return {'message': 'Logged out successfully'}, 200

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
