from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from mcrcon import MCRcon


app = Flask(__name__)
app.secret_key = 'disePVP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
manager = LoginManager(app)

mcr = MCRcon("217.182.216.255", "D3i2s6e4", port=9551)

from sweater import models, routes

db.create_all()
