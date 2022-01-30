import flask_login


class User(flask_login.UserMixin):
    role = 'viewer'

    def __init__(self, email=None, name=None, password=None, role='viewer'):
        self.email = email
        self.password = password
        self.name = name
        self.role = role
