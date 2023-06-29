from datetime import timedelta 
import os

BASE_DIR = os.path.dirname(os.path.realpath(__file__))




class Config():
    SECRET_KEY = os.environ.get("SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    MONGO_URI = 'mongodb://localhost:27017/Locale'


class DevConfig():
    DEBUG = True

class TestConfig():
    TESTING = True

class ProdConfig():
    DEBUG = False
    MONGO_URI = ('MONGO_URI')



config_dict = {
    'dev': DevConfig,
    'test': TestConfig,
    'prod': ProdConfig
}
