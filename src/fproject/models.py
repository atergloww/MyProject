from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(30), nullable=False)
    title = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Integer, nullable=False)
    text = db.Column(db.String(2000), nullable=False)

    is_deleted = db.Column(db.Boolean, default = False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)

    name = db.Column(db.String(20), nullable=False)
    about_me = db.Column(db.String(1000), nullable=True)
    phone_number = db.Column(db.String(10), nullable=True)

    is_deleted = db.Column(db.Boolean, default = False)

    def __repr__(self):
        return f'<User {self.username}>'
