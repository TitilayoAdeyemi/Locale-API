from flask import Flask, Blueprint, request
from flask_restx import Namespace, Api, fields
import bcrypt, string, secrets
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from http import HTTPStatus
from werkzeug.exceptions import BadRequest, Conflict
from flask.views import MethodView
from api.models.schema import mongo



app = Flask(__name__)

auth_routes = Blueprint('auth_routes', __name__)


api = Api(app)

auth_namespace = Namespace('auth', description='A Namespace for authentication')

api.add_namespace(auth_namespace)

signup_model = auth_namespace.model(
    'signup', {
        'name' : fields.String(required = True, decription = 'name'),
        'email': fields.String(required=True, description='email'),
        'password' : fields.String(required=True, description ='password')
        
    }
)

login_model = auth_namespace.model(
    'Login', {
        'email' : fields.String(required=True, description = 'email'),
        'password' : fields.String(required = True, description='password')
    }
)

user_model = auth_namespace.model('User', {
    'name': fields.String(required=True, description='name'),
    'email': fields.String(required=True, description='Emailxz'),
    'apikey': fields.String(description='API Key')
})


def generate_apikey(length=32):
    """Generates a random API key."""
    characters = string.ascii_letters + string.digits
    apikey = ''.join(secrets.choice(characters) for _ in range(length))
    return apikey


class SignUp(MethodView):
    def post(self):
        data = request.get_json()
        try:
            name = data['name']
            email = data['email']
            password = data['password']
            
            existing_user = mongo.db.users.find_one({'email': email})
            
            if existing_user:
                return {'message': 'User already exists'}, 409

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            apikey = generate_apikey()
            
            user = {
                'name': name,
                'email' : email,
                'password': hashed_password,
                'apikey': generate_apikey()
            }
            mongo.db.users.insert_one(user)

            return {
                'message': 'User registered successfully'
                # 'Your apikey is ' : apikey
                    }, 201
        
        except Exception as e:
                raise Conflict(f'User with email {data.get("email")} already exists')

register_view = SignUp.as_view("register")
auth_routes.add_url_rule("/api/auth/register",view_func=register_view,methods=["POST"])

    
class Login(MethodView):
    def post(self):

        data = request.get_json()
        
        try:
            email = data['email']
            password = data['password']
            
            # Retreive the user from the db
            user = mongo.db.users.find_one({'email': email})
            if not user:
                return {'message': 'Invalid credentials'}, 401
            
            print(user["password"])
            hashed_password = user["password"]
            
            password_bytes = password.encode('utf-8')
            
            password_matched = bcrypt.checkpw(password_bytes, hashed_password)
            if password_matched:
                access_token = create_access_token(identity=user["email"])
                refresh_token = create_refresh_token(identity=user["email"])

                
                response = {
                    'access_token': access_token,
                    'refresh_token': refresh_token
                }
                
                return response, HTTPStatus.OK
            else:
                return {'message': 'Invalid credentials'}, 401
            
        except:
            raise BadRequest('Invalid username or password')

            
     
    
login_view = Login.as_view("login")
auth_routes.add_url_rule("/api/auth/login",view_func=login_view,methods=["POST"])
   
class Refresh(MethodView):
    @jwt_required(refresh=True)
    def post(self):
        try:
            name = get_jwt_identity()

            access_token = create_access_token(identity=name)
            

            return{"access_token": access_token}, HTTPStatus.OK
        
        except:
            return {"message": "Refresh token has expired"}, HTTPStatus.UNAUTHORIZED
            
    
refresh_view = Login.as_view("refresh")
auth_routes.add_url_rule("/api/auth/refresh",view_func=refresh_view,methods=["POST"])
   
 