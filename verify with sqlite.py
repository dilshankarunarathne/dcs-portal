from flask_login import UserMixin
from datetime import datetime
from . import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # workouts = db.relationship('Workout', backref='author', lazy=True)
    reg_no = db.Column(db.String(25), db.ForeignKey('student.reg_no'))
    # student = db.relationship('Student', backref='user', lazy=True)



class Student(db.Model):
    name = db.Column(db.Text, nullable=False)
    reg_no = db.Column(db.Text, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.Text(100), unique=True)
    fullname = db.Column(db.Text(250))
    phone = db.Column(db.Text(12))
    status = db.Column(db.Text)
    race = db.Column(db.Text)
    district = db.Column(db.Text)




# class Workout(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     pushups = db.Column(db.Integer, nullable=False)
#     date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
#     comment = db.Column(db.Text, nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
