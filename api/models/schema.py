from pymongo import MongoClient
from flask_pymongo import PyMongo
from flask import Flask

app = Flask(__name__)

app.config['MONGO_URI'] = 'mongodb://localhost:27017/Locale'  # Replace with your MongoDB URI
mongo = PyMongo(app)
client = MongoClient('mongodb://localhost:27017')
db = client['Locale']
users_collection = db['users']



mongo = PyMongo(app)
client = MongoClient('mongodb://localhost:27017')
db = client['Locale']
users_collection = db['users']



# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Set the token expiration time
# app.config['JWT_SECRET_KEY'] ="timedelta(hours=1)  # Set the token expiration time"

# app.config['MONGO_URI'] = 'mongodb://localhost:27017/Locale'  # Replace with your MongoDB URI
# mongo = PyMongo(app)
# client = MongoClient('mongodb://localhost:27017')
# db = client['Locale']
# users_collection = db['users']