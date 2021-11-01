import json
from flask_login import UserMixin
from collections import OrderedDict

from sweater import db, manager
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(16), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True)
    verified = db.Column(db.Boolean, default=False, nullable=False)
    reg_date = db.Column(db.String(128))
    permission = db.Column(db.String(1))
    fakeUser = db.Column(db.String(16))
    ip = db.Column(db.String(255))
    def is_active(self):
        """True, as all users are active."""
        return True

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False
        
@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
