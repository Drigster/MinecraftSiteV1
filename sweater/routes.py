import os
import re
import json
from os import path
from datetime import datetime
from flask import render_template, redirect, url_for, request, flash, json, jsonify, abort, send_from_directory
from flask_login import login_user, login_required, logout_user, current_user
from flask_mail import Message
from itsdangerous import SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from mcstatus import MinecraftServer

from sweater import db, app, s, mail
from sweater.models import User
from sweater.classes import Skin, Log

log = Log()

@app.route('/', methods=['GET'])
def main():
	return render_template('index.html')

@app.errorhandler(404)
def not_found(e):
	return render_template("404.html")

@app.route('/favicon', methods=['GET'])
def favicon():
	return send_from_directory(app.config['IMGS_DEST'], 'logo.png')

@app.route('/download', methods=['GET'])
def download():
	return redirect("http://213.168.10.192:9274/Launcher.exe")

@app.route('/register', methods=['GET', 'POST'])
def register():
	login = str(request.form.get('login'))
	email = str(request.form.get('email'))
	password = str(request.form.get('password'))
	password2 = str(request.form.get('password2'))
	user = User.query.filter(User.login.ilike(login)).first()
	email_check = User.query.filter(User.email.ilike(email)).first()

	if request.method == 'POST':
		if not (login or password or password2 or email):
			flash('Пожалуйста заполните все поля!')
		elif not re.search("^[A-Za-z0-9_]{3,16}$", login):
			flash('Никнейм имеет недопустимые символы')
		elif user != None:
			flash('Профиль с таким никнеймом уже существует!!!')
		elif email_check != None:
			flash('Эта почта занята!')
		elif len(password) < 6:
			flash('Пароль слишком короткий(минимум: 6)')
		elif password != password2:
			flash('Пароли не совподают!')
		else:
			hash_pwd = generate_password_hash(password)
			new_user = User(login=login, email=email, password=hash_pwd, permission=0, reg_date=datetime.now().strftime("%d.%m.%y:%H.%M"))
			db.session.add(new_user)
			db.session.commit()

			login_user(new_user)

			send_confirmation_email(email)

			log.log(f"Зарегистрирован - {login}")

			return redirect(url_for('login_page'))
	return render_template('register.html')

@app.route('/confirm/<token>')
def email_confirm(token):
	try:
		email = s.loads(token, max_age=3600)
	except SignatureExpired:
		return render_template('confirm.html', message="Истекло время не подтверждение!")
	except Exception:
		return render_template('confirm.html', message="Неизвестная ошибка, попробуйте ешё раз!")
	user = User.query.filter(User.email.ilike(email)).first()
	user.verified = True
	db.session.commit()
	log.log(f"Подтвержна почта - {user.login}")
	return render_template('confirm.html', message="Почта подтверждена!")
	

@app.route('/login', methods=['GET', 'POST'])
def login_page():
	if current_user.is_authenticated:
		return redirect(url_for('profile'))
	else:
		login = request.form.get('login')
		password = request.form.get('password')

	if request.method == 'POST':
		user = User.query.filter_by(login=login).first()
		if not (login or password):
			flash("Введите никнейм и пароль!")
		elif not user:
			flash("Зарегистрируйтесь!")
		elif check_password_hash(user.password, password):
			try:
				login_data = json.loads(user.ip)
			except Exception:
				login_data = {}
			login_data[datetime.now().strftime("%d.%m.%y:%H.%M")] = request.remote_addr
			user.ip = json.dumps(login_data)
			db.session.commit()

			login_user(user)
			next_page = request.args.get('next')

			return redirect(next_page or url_for('profile'))
		else:
			flash("Пароль не верен!")
	return render_template('login.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	return redirect(url_for('main'))


@app.after_request
def redirect_to_signin(response):
	if response.status_code == 401:
		return redirect(url_for('login_page') + '?next=' + request.url)

	return response


@app.route('/admin', methods=['GET', 'POST'])
def admin():
	if current_user.get_id() != None:
		if current_user.permission > 0:
			try:
				mc_V = MinecraftServer.lookup(app.config['SERVER_VANILA'])
				status_V = mc_V.status()
			except Exception:
				status_V = False
			try:
				mc_M = MinecraftServer.lookup("disepvp.ee:666")
				status_M = mc_M.status()
			except Exception:
				status_M = False

			users = User.query.all()
			user = current_user

			if request.method == 'POST':
				if request.form.get('sumbit') == 'reset_pwd':
					pwd = 'none'
					usr = request.form.get('user')
					user = User.query.filter_by(login=usr).first()
					pwd_hash = generate_password_hash(pwd)
					user.password = pwd_hash
					db.session.commit()
					users = User.query.all()
					log.log(f"Сброшен пароль для пользователя - {usr}")
				elif request.form.get('sumbit') == 'delete_ac':
					usr = request.form.get('user')
					user = User.query.filter_by(login=usr).first()
					db.session.delete(user)
					db.session.commit()
					users = User.query.all()
					log.log(f"Удалён пользователь - {usr}")
				elif request.form.get('sumbit') == 'login_as':
					usr = request.form.get('user')
					if user.fakeUser == usr:
						user.fakeUser = None
						log.log(f"Убран фейковый пользователь - {usr} для пользователя {user.login}")
					else:
						user.fakeUser = usr
						db.session.commit()
						users = User.query.all()
						log.log(f"Добавлен фейковый пользователь - {usr} для пользователя {user.login}")
				elif request.form.get('sumbit') == 'reload':
					users = User.query.all()
				else:
					log.log(f"FUCK")

			return render_template('admin.html', users=users, status_V=status_V, status_M=status_M)
	else:
		abort(404)

def allowed_file(filename):
	return '.' in filename and \
		   filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
	skin_image = url_for('get_body', username=f"{current_user.login}")
	old_email = current_user.email
	email = request.form.get('email')
	password = request.form.get('password')
	new_password1 = request.form.get('new_password1')
	new_password2 = request.form.get('new_password2')
	
	if request.method == 'POST':
		
		if request.form.get('sumbit') == 'skin':
			try:
				if 'skin' not in request.files:
					flash('ERROR')
					return redirect(request.url)	
				skin = request.files['skin']
				if skin.filename == '':
					flash('Файл не выбран')
					return redirect(request.url)	
				if skin and allowed_file(skin.filename):
					Skin_class = Skin(skin, current_user.login)
					Skin_class.save()
					return render_template('profile.html', skin_image=url_for('get_body', username=f"{current_user.login}"), head_image=url_for('get_head', username=f"{current_user.login}"))
			except RequestEntityTooLarge:
				flash('Файл слишком большой')
		elif request.form.get('sumbit') == 'password':
			if not (password or new_password1 or new_password2):
				flash('Пожалуйста заполните все поля!')
			elif not check_password_hash(current_user.password, password):
				flash('Пароль не верен!')
			elif new_password1 != new_password2:
				flash('Пароли не совподают!')
			else:
				hash_pwd = generate_password_hash(new_password1)
				current_user.password = hash_pwd
				db.session.commit()
				log.log(f"Изменён пароль - {current_user.login}")
				flash('Пароль успешно изменён!')
		elif request.form.get('sumbit') == 'email':
			if not email:
				flash('Пожалуйста заполните поле!')
			email_check = User.query.filter(User.email.ilike(email)).first()
			if email_check != None:
				flash('Эта почта занята!')
			elif old_email != email:
				current_user.email = email
				db.session.commit()
				log.log(f"Изменена почта - {current_user.login}")
				send_confirmation_email(email)
				flash('Почта успешно изменена!')
		elif request.form.get('sumbit') == 'verify':
			flash('Ссылка для верефикации отправлена!')
			send_confirmation_email(current_user.email)
		elif request.form.get('sumbit') == 'delete_date':
			dates = request.form.getlist('date')
			if dates == None:
				flash('Вы не выбрали дату!')
			else:
				for date in dates:
					log.log(f"{date}")
					login_data = json.loads(current_user.ip)
					login_data.pop(date)
					current_user.ip = json.dumps(login_data)
					db.session.commit()
					log.log(f"{current_user.ip}")

	return render_template('profile.html', skin_image=skin_image)

@app.route('/auth', methods=['POST'])
def to_bot_message():
	json_string = request.json
	user = User.query.filter(User.login.ilike(json_string['username'])).first()
	print(json_string['username'])
	if user == None:
		return jsonify(
			error="Зарегистрируйтесь прежде чем войти!"
		)
	elif user.verified == False:
		return jsonify(
			error="Пожалуйста подтвердите вашу почту!"
		)
	elif check_password_hash(user.password, json_string['password']):
		if user.fakeUser != None:
			print(f"{user.login} выполнил вход как {user.fakeUser}")
			usr = user.fakeUser
			user.fakeUser = None
			db.session.commit()
			return jsonify(
				username=usr,
				permissions=user.permission
			)
		else:
			try:
				login_data = json.loads(user.ip)
			except Exception:
				login_data = {}
			login_data[datetime.now().strftime("%d.%m.%y:%H.%M")] = request.remote_addr
			user.ip = json.dumps(login_data)
			db.session.commit()
			print(json_string['username'], user.login)
			return jsonify(
				username=user.login,
				permissions=user.permission
			)
	else:
		return jsonify(
			error="Неверный Никнейм или пароль!"
		)

@app.route('/skin/head/<username>.png')
def get_head(username):
	if path.exists(f"{app.config['UPLOADED_SKINS_DEST']}/{username}_head.png"):
		return send_from_directory(app.config['UPLOADED_SKINS_DEST'], f"{username}_head.png", as_attachment=False)
	return send_from_directory(app.config['UPLOADED_SKINS_DEST'], f"default_head.png", as_attachment=False)

@app.route('/skin/body/<username>.png')
def get_body(username):
	if path.exists(f"{app.config['UPLOADED_SKINS_DEST']}/{username}_body.png"):
		return send_from_directory(app.config['UPLOADED_SKINS_DEST'], f"{username}_body.png", as_attachment=False)
	return send_from_directory(app.config['UPLOADED_SKINS_DEST'], f"default_body.png", as_attachment=False)

@app.route('/skin/<username>.png')
def get_skin(username):
	if path.exists(f"{app.config['UPLOADED_SKINS_DEST']}/{username}.png"):
		return send_from_directory(app.config['UPLOADED_SKINS_DEST'], f"{username}.png", as_attachment=False)
	return send_from_directory(app.config['UPLOADED_SKINS_DEST'], f"default.png", as_attachment=False)

@app.route('/servers/vanila')
def vanila():
	chunk = ['0;[];2021-10-07T22:55:19',
			'0;[];2021-10-07T23:00:19',
			'0;[];2021-10-07T23:05:19',
			'0;[];2021-10-07T23:10:20',
			'1;[];2021-10-07T23:15:20',
			'1;[];2021-10-07T23:20:20',
			'2;[];2021-10-07T23:25:20',
			'0;[];2021-10-07T23:30:20',
			'0;[];2021-10-07T23:35:20',
			'0;[];2021-10-07T23:40:20',
			'0;[];2021-10-07T23:45:20'
]
	return render_template('vanila.html', chunk=chunk)


def send_confirmation_email(email):
    token = s.dumps(email)

    msg = Message('Подтверждение почты', recipients=[email])

    link = url_for('email_confirm', token=token, _external=True)

    msg.body = 'Для подтверждения почты перейдите по ссылке: \n{}'.format(link)

    mail.send(msg)
    log.log(f"Отправлено подтверждение на - {email}")

