from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, url_for, redirect, request, flash, abort
from models import Post, User, db
from flask_login import LoginManager, login_user, current_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret-key-goes-here'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

db.init_app(app)

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('user'))
    else:
        return render_template('index.html', current_user=current_user)

@app.route('/new')
def new():
    return render_template('new.html', current_user=current_user)

@app.route('/popular')
def popular():
    return render_template('popular.html', current_user=current_user)

@app.route('/rubrics')
def rubrics():
    return render_template('rubrics.html', current_user=current_user)

@app.route('/error')
def error():
    abort(404)

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if current_user.is_authenticated:
        return redirect(url_for('user'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password) and user.is_deleted == False:
            login_user(user)
            return redirect(url_for('user'))
        else:
            flash('Неправильный логин или пароль:(')
    return render_template('auth.html')

@app.route('/user', methods=['GET', 'POST'])
def user():
    if current_user.is_authenticated == False:
        return redirect(url_for('auth'))
    
    return render_template("profile.html", user=current_user)

@app.route('/add_acc', methods=['GET', 'POST'])
def add_acc():
    if current_user.is_authenticated:
        return redirect(url_for('user'))
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        about_me = request.form['about_me']
        phone_number = request.form['phone_number']

        user = User.query.filter_by(username=username).first()

        if (username == "" or password == "" or name == "" or phone_number == None):
           flash('Некоторые поля не заполнены')
        else:
            if (user):
                flash('Такой аккаунт уже существует')
            else:
                new_user = User(username=username, password=generate_password_hash(password), name=name, about_me = about_me, phone_number=phone_number)
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('auth'))
    return render_template("add_acc.html")

@app.route('/edit', methods=['GET', 'POST'])
def edit():
    if request.method == 'POST':
        current_user.username = request.form['username']
        current_user.password = generate_password_hash(request.form['password'])
        current_user.name = request.form['name']
        current_user.about_me = request.form['about_me']
        current_user.phone_number = request.form['phone_number']

        db.session.commit()
        return redirect(url_for('user'))
    return render_template('edit.html', user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/delete', methods=['GET', 'POST'])
def delete():
    if request.method == 'POST':
        current_user.is_deleted = True
        db.session.commit()
        logout_user()
        return redirect(url_for('index'))
    return render_template('delete.html', user=current_user)

@app.errorhandler(400)
def bad_request(e):
    return render_template('400.html'), 400

@app.errorhandler(401)
def unauthorized(e):
    return render_template('401.html'), 401

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found_error(e):
    return render_template('404.html'), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return render_template('405.html'), 405

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(501)
def not_implemented(e):
    return render_template('501.html'), 501

@app.errorhandler(502)
def bad_gateway(e):
    return render_template('502.html'), 502

@app.errorhandler(503)
def service_unavailable(e):
    return render_template('503.html'), 503

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
