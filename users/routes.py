from flask import Blueprint
from users.resources import Registration, Login, Profile, ResetPasswordRequest, ResetPassword, ChangePassword

users = Blueprint("test_users", __name__)

users.add_url_rule("/register", view_func=Registration.as_view("register"))
users.add_url_rule("/login", view_func=Login.as_view("login"))
users.add_url_rule("/profile", view_func=Profile.as_view("profile"))
users.add_url_rule("/reset_password_request", view_func=ResetPasswordRequest.as_view("reset_password_request"))
users.add_url_rule("/reset_password", view_func=ResetPassword.as_view("reset_password"))
users.add_url_rule("/change_password", view_func=ChangePassword.as_view("change_password"))
