from flask_login import UserMixin
from datetime import datetime
from . import db


class MasterDB(db.Model):
    __tablename__ = 'masterdb'
    __table_args__ = {'schema': 'schema_any'}
    __abstract__ = True



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    reg_no = db.Column(db.String(25), db.ForeignKey('student.reg_no'))
    account_verification = db.Column(db.Boolean, default=False, nullable=False) 
    # student_inst = db.relationship('Student', backref='user', lazy=True, uselist=False)

# uselist=False     to have a one-to-one relationship


class Student(db.Model):
    name = db.Column(db.Text, nullable=False)
    reg_no = db.Column(db.Text, primary_key=True) 
    email = db.Column(db.Text(100), unique=True)
    fullname = db.Column(db.Text(250))
    phone = db.Column(db.Text(12))
    status = db.Column(db.Text)
    race = db.Column(db.Text)
    district = db.Column(db.Text)
    
    
    
class Hashes(db.Model):
    reg_no = db.Column(db.Text)    # removed , db.ForeignKey('student.reg_no')
    # user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # added new
    email = db.Column(db.Text)
    hash = db.Column(db.Text, primary_key=True)
    time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)



# db.execute( "CREATE TABLE IF NOT EXISTS sent_hashes ("
#             "reg_no TEXT NOT NULL,"
#             "email TEXT,"
#             "hash TEXT NOT NULL PRIMARY KEY ,"
#             "time TIMESTAMP)")

# class Workout(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     pushups = db.Column(db.Integer, nullable=False)
#     date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
#     comment = db.Column(db.Text, nullable=False)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



# from v3 import db, create_app
# db.create_all(app=create_app())