import flask_login
from . import app
from flask import render_template

from .settings import users
from .user import User


login_manager = flask_login.LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def user_loader(email):
    user_filtered = list(filter(lambda item: item.email == email, users))
    if len(user_filtered) == 0:
        return

    user = User()
    user.id = email
    user.role = user_filtered[0].role
    return user


@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    user_filtered = list(filter(lambda item: item.email == email, users))
    if len(user_filtered) == 0:
        return

    user = User()
    user.id = email
    user.role = user_filtered[0].role
    return user


@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('login.html')
