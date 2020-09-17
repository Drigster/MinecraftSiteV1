from flask import render_template, redirect, url_for, request, flash, json, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from sweater import app, db, mcr
from sweater.models import Message, User


@app.route('/', methods=['GET'])
def main():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    user = User.query.filter_by(login=login).first()
    if user != None:
        userlogin = user.login
    else:
        userlogin = None

    if request.method == 'POST':
        if userlogin == login:
            flash('Профиль с таким никнеймом уже существует!!!')
        elif not (login or password or password2):
            flash('Пожалуйста заполните все поля!')
        elif password != password2:
            flash('Пароли не совподают!')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd, permission=0)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login_page'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    else:
        login = request.form.get('login')
        password = request.form.get('password')

        if login and password:
            user = User.query.filter_by(login=login).first()

            if user and check_password_hash(user.password, password):
                login_user(user)

                next_page = request.args.get('next')

                return redirect(next_page or url_for('profile'))
            else:
                flash('Логин или пароль неверны!')
        else:
            flash('Пожалуйста заполните все поля!')
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
@login_required
def admin():
    if current_user.permission > 0:
        users = User.query.all()
        
        if request.method == 'POST':
            pwd = 'none'
            user = User.query.filter_by(login=request.form.get('user')).first()
            pwd_hash = generate_password_hash(pwd)
            user.password = pwd_hash
            db.session.commit()

        return render_template('admin.html', users=users)

    else:
        pass

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    password = request.form.get('password')
    new_password1 = request.form.get('new_password1')
    new_password2 = request.form.get('new_password2')

    if request.method == 'POST':
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
            flash('Пароль успешно изменён!')

    return render_template('profile.html')

@app.route('/auth', methods=['POST'])
def to_bot_message():
    json_string = request.json
    user = User.query.filter_by(login=json_string['username']).first()

    if user == None:
        return jsonify(
            error="Зарегистрируйтесь прежде чем войти!"
        )
    elif check_password_hash(user.password, json_string['password']):
        return jsonify(
            username=json_string['username'],
            permissions=user.permission
        )
    else:
        return jsonify(
            error="Неверный логин или пароль!"
        )
