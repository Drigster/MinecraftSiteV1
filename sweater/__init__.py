import locale
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from passwords import secretKey, eMailPassword

app = Flask(__name__)
app.secret_key = secretKey
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

manager = LoginManager(app)
s = URLSafeTimedSerializer(app.secret_key)
locale.setlocale(locale.LC_ALL, ('RU','UTF8'))

app.config['IMGS_DEST'] = '/home/minecraft/site/#source/img'
app.config['LAUNCHER_EXE_DEST'] = '/home/minecraft/launcher/updates'
app.config['LOGS_DEST'] = '/home/minecraft/site/#source/logs'

app.config['MAX_CONTENT_LENGTH'] = 16 * 64 * 64
app.config['UPLOADED_SKINS_DEST'] = '/home/minecraft/site/#source/skins'
app.config['UPLOADED_CAPES_DEST'] = '/home/minecraft/site/#source/capes'
app.config['ALLOWED_EXTENSIONS'] = set(['png'])

app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_USERNAME'] = "authdisepvp@gmail.com"
app.config['MAIL_PASSWORD'] = eMailPassword
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_DEFAULT_SENDER'] = "authdisepvp@gmail.com"

app.config['SERVER_VANILA'] = "disepvp.ee:623"
app.config['SERVER_MODED'] = "disepvp.ee:666"

mail = Mail(app)

from sweater import routes, models, filters, classes
db.create_all()