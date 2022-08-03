import os
from dotenv import load_dotenv
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_swagger_ui import get_swaggerui_blueprint
from config import Config

load_dotenv()

db = SQLAlchemy()
bcrypt = Bcrypt()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('SQLALCHEMY_DATABASE_URI')
    app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY')

    SWAGGER_URL = '/swagger'
    API_URL = '/static/swagger.json'
    SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'app_name': "Flask API Swagger"
        }
    )
    app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)
    db.init_app(app)
    from users import models
    Migrate(app, db)
    db.init_app(app)
    jwt = JWTManager(app)

    from users.routes import users
    app.register_blueprint(users)

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
