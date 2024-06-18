from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, url_for, redirect, request, flash
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
    return render_template('error.html')

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


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
