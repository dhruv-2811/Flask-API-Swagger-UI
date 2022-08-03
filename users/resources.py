from flask import request
from flask_api import status
from flask_restful import Resource
from sqlalchemy.exc import DataError
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from app import bcrypt, db
from users.models import User
from users.utils import get_reset_token, verify_reset_token
from users.validations import validate_email, validate_password


class Registration(Resource):

    def post(self):
        user_json = request.get_json()

        try:
            user = User.query.filter_by(email=user_json['email']).first()
            if user:
                return {"data": [],
                        "message": "user with this email id already exists please choose different email",
                        "status": "false"
                        }, status.HTTP_400_BAD_REQUEST

            if not validate_email(user_json["email"]):
                return {"data": [],
                        "message": "Please enter proper email",
                        "status": "false"
                        }, status.HTTP_400_BAD_REQUEST

            if not validate_password(user_json["password"]):
                return {"data": [],
                        "message": "Please enter proper password",
                        "status": "false"
                        }, status.HTTP_400_BAD_REQUEST
            hashed_password = bcrypt.generate_password_hash(user_json['password']).decode('utf-8')
            user_object = User(email=user_json['email'], password=hashed_password)
            user_object.save_to_db()
            return {"data": request.get_json(),
                    "message": "User Register Successfully",
                    "status": "true"
                    }, status.HTTP_201_CREATED
        except (KeyError, AttributeError, DataError) as err:
            return {"data": [],
                    "message": "Please enter proper data",
                    "status": "false"
                    }, status.HTTP_400_BAD_REQUEST


class Login(Resource):

    def post(self):
        login_json_data = request.get_json()
        try:
            user = User.query.filter_by(email=login_json_data["email"]).first()
            if not user:
                return {"data": [],
                        "message": "email doesn't exists",
                        "status": "false"
                        }, status.HTTP_404_NOT_FOUND
            if bcrypt.check_password_hash(user.password, login_json_data["password"]):
                access_token = create_access_token(identity=user.id)
                # access_token = "abcde"
                return {"message": "Login Successfully",
                        "data": {"access_token": access_token},
                        "status": "true"
                        }, status.HTTP_200_OK
            else:
                return {"data": [],
                        "message": "Invalid password",
                        "status": "false"
                        }, status.HTTP_400_BAD_REQUEST
        except (KeyError, AttributeError) as err:
            return {"data": [],
                    "message": "Please enter proper data",
                    "status": "false"
                    }, status.HTTP_400_BAD_REQUEST


class Profile(Resource):
    decorators = [jwt_required()]

    def get(self):
        user = User.query.filter_by(id=get_jwt_identity()).first()
        return {"data": {"id": user.id, "email": user.email},
                "message": "user data fetched successfully",
                "status": "true"
                }, status.HTTP_200_OK


class ResetPasswordRequest(Resource):
    """class for getting the home page if user is already logged in and posting the data"""

    def post(self):
        """method for checking if the email is valid """
        reset_request_json = request.get_json()
        try:
            user = User.query.filter_by(email=reset_request_json["email"]).first()
            if user:
                token = get_reset_token(user)
                return {"data": token,
                        "message": "use this token to reset the password.",
                        "status": "true"
                        }, status.HTTP_200_OK
            return {"data": [],
                    "message": "Invalid email id. Please enter valid email.",
                    "status": "false"
                    }, status.HTTP_404_NOT_FOUND

        except KeyError as err:
            return {"data": [],
                    "message": "Enter proper data",
                    "status": "false"
                    }, status.HTTP_400_BAD_REQUEST


class ResetPassword(Resource):
    """class for getting the home page if the user is already logged in and posting the data of the user after the
     password reset"""

    def post(self):
        """method for verifying the token to reset the password and creating new password for the user"""
        reset_password_json = request.get_json()

        try:
            user = verify_reset_token(reset_password_json["token"])
            if user is None:
                return {"data": [],
                        "message": "That is an invalid or expired token",
                        "status": "false"
                        }, status.HTTP_400_BAD_REQUEST

            if not validate_password(reset_password_json["password"]):
                return {"data": [],
                        "message": "Please enter proper password",
                        "status": "false"
                        }, status.HTTP_400_BAD_REQUEST
            hashed_password = bcrypt.generate_password_hash(reset_password_json["password"]).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            return {"data": [],
                    "message": "Your password has been updated! You can now log in",
                    "status": "true"
                    }, status.HTTP_200_OK

        except KeyError as err:
            return {"data": [],
                    "message": "Enter proper data",
                    "status": "false"
                    }, status.HTTP_400_BAD_REQUEST


class ChangePassword(Resource):
    decorators = [jwt_required()]

    def post(self):
        password_json_data = request.get_json()
        user = User.query.filter_by(id=get_jwt_identity()).first()
        try:
            # if password_json_data["current_password"] == user.password:
            if bcrypt.check_password_hash(user.password, password_json_data["current_password"]):
                if not validate_password(password_json_data["new_password"]):
                    return {"data": [],
                            "message": "Please enter proper password",
                            "status": "false"
                            }, status.HTTP_400_BAD_REQUEST

                user.password = bcrypt.generate_password_hash(password_json_data["new_password"]).decode('utf-8')
                db.session.commit()
            else:
                return {"data": [],
                        "message": "Invalid current password",
                        "status": "false"
                        }, status.HTTP_400_BAD_REQUEST
        except (KeyError, AttributeError) as err:
            return {"data": [],
                    "message": "Please enter proper data",
                    "status": "false"
                    }, status.HTTP_400_BAD_REQUEST
        return {"data": [],
                "message": "Password changed successfully",
                "status": "true"
                }, status.HTTP_200_OK
