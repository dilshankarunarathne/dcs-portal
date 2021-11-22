from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
import datetime
from .models import User
from .models import Student
from .models import Hashes
from . import db
from . import send_mail
import secrets


verify = Blueprint('verify', __name__)


def check_student(given_reg_no) -> bool:
    # see if the reg no is the same
    # TODO - way to check if the user is in fact a student in our batch
    student = Student.query.filter_by(reg_no=given_reg_no).first_or_404()
    if student:
        return True
    return False

service = send_mail.gmail_authenticate()
reciever_email = "user.ftp.server@gmail.com"
mail_subject = "Verification mail from DCS-Portal"



#TODO - change this to remote host
@verify.route('/sent-verification')
def verification_sending():
    generated_key = session.get('key', None)
    reg_no_to_verify = session.get('reg_no', None)
    url_to_send = "http://127.0.0.1:5000/verify-email?key={}&reg={}".format(generated_key, reg_no_to_verify) 
    print ("Sending verification email...")
    rendered_page =  render_template('sent-verification.html', verification_link=url_to_send)
    send_mail.send_message(service, reciever_email, mail_subject, rendered_page)
    
    return render_template('check-email.html')

#   below here, are the processing of clicked email verification link


def verify_gotten_email(got_reg_no, got_key) -> bool :
    print("Student email-hash verification - Called")
    
    student_to_verify = User.query.filter_by(reg_no=got_reg_no).first()
    if student_to_verify:
        print("Student found {}".format(student_to_verify.name))
    
    hash_in_db = Hashes.query.filter_by(reg_no=student_to_verify.reg_no).first_or_404()

    if(got_key == hash_in_db.hash):
        print("Verification was successful for {}".format(got_reg_no))
        return True
    else:
        print("Verification failed! : {}".format(got_reg_no))
        return False


# working
@verify.route('/verify-email')
def verify_email():
    key = request.args.get('key')
    reg_no = request.args.get('reg')
    # exception handled for url typos
    print("Verifying {} - {}".format(reg_no, key))
    try:
        verified = verify_gotten_email(reg_no, key)
        if (verified):
            # rows_changed = User.query.filter_by(role='admin').update(dict(permission='add_user'))
            # rows_changed = User.query.filter_by(reg_no=got_reg_no).first().update(account_verification=True)
            cur_user = User.query.filter_by(reg_no=reg_no).first()
            cur_user.account_verification = True
            db.session.commit()
            print("Verified account!")
        return redirect(url_for('verify.verification_result', result=verified))
    except Exception as e:
        return "Error! {}".format(e)


# working
@verify.route('/verification-result')
@verify.route('/verification-result/<result>')
def verification_result(result=False):
    try:
        return render_template('verification-result.html', result=result)
    except Exception as e:
        return "Error! {}".format(e)
    



