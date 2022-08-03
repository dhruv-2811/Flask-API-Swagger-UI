import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """class which stores important configuration information required for different usages"""

    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
