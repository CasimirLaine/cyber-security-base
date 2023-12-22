from typing import Optional

from flask import Flask, request, render_template, flash, url_for, redirect, session
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256
from sqlalchemy import text

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    sensitive_data = db.Column(db.String(80), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def _clear_flash():
    session.pop('_flashes', None)


def _send_flash(msg, category):
    _clear_flash()
    flash(msg, category)


def _login_func() -> Optional[User]:
    username = request.args.get('username')
    password = request.args.get('password')
    query = text(f"SELECT id FROM user WHERE username = '{username}' AND password = '{password}'")
    try:
        result = db.session.execute(query).fetchone()
    except Exception as e:
        return None
    if not result:
        return None
    return User.query.get(int(result[0]))


def _login_func_safe() -> Optional[User]:
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return user


def _common_login_endpoint(fetch_func, redirect_endpoint, template):
    if request.method == 'POST':
        user = fetch_func()
        if user:
            login_user(user)
            _send_flash('Logged in successfully!', 'success')
            return redirect(url_for(redirect_endpoint, user_id=user.id))
        else:
            _send_flash('Invalid credentials.', 'danger')
    return render_template(template)


@app.route('/login', methods=['GET', 'POST'])
def login():
    return _common_login_endpoint(_login_func, 'profile', 'login.html')


@app.route('/login_fixed', methods=['GET', 'POST'])
def login_fixed():
    return _common_login_endpoint(_login_func_safe, 'profile_fixed', 'login_fixed.html')


# http://127.0.0.1:5000/login?username=admin%27OR%271%27=%271%27--&password=anything

@app.route('/profile/<user_id>')
@login_required
def profile(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        _send_flash('User not found!', 'danger')
        return redirect(url_for('login'))
    return render_template('profile.html', user=user)


@app.route('/profile_fixed/<user_id>')
@login_required
def profile_fixed(user_id):
    if str(current_user.id) == str(user_id):
        return render_template('profile.html', user=current_user)
    else:
        return redirect(url_for('login_fixed'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    _send_flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))


with app.app_context():
    db.create_all()
    default_users = [
        {
            "username": "admin",
            "password": "adminpass",
            "sensitive_data": "Admin secret"
        },
        {
            "username": "user1",
            "password": "user1pass",
            "sensitive_data": "User 1 data"
        },
        {
            "username": "user2",
            "password": "user2pass",
            "sensitive_data": "User 2 data"
        }
    ]
    for user_data in default_users:
        user = User(**user_data)
        user.set_password(user_data["password"])
        db.session.add(user)
    db.session.commit()

if __name__ == '__main__':
    app.run(debug=True, passthrough_errors=True, port=5000)
