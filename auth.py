from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
from .models import Hashes
from . import db
from . import send_mail
import secrets
import datetime

auth = Blueprint('auth', __name__)


@auth.route('/login')
def login():
    return render_template('login.html')


#TODO add a way to restrict login untill the account is verified
@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))  # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    # but we still need to check, if the account is verified
    if (user.account_verification == False):
        flash('Please verify your account before logging in!')
        return render_template('check-email.html')
    
    # if the account is verified, we can let the user log-in
    login_user(user, remember=remember)

    return redirect(url_for('main.profile'))


@auth.route('/signup')
def signup():
    return render_template('signup.html')


@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    reg_no = request.form.get('reg_no')

    # if this returns a user, then the email already exists in database
    user = User.query.filter_by(email=email).first()

    print(user)

    if user:  # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))
    
    # create new user with the form data. Hash the password so plaintext version isn't saved.
    new_user = User(email=email, name=name, 
                    password=generate_password_hash(password, method='sha256'), reg_no=reg_no)

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    # save the hash info on table
    hash_key = "DCSPTLHS" + str(secrets.token_urlsafe(16))
    session['key'] = hash_key
    session['reg_no'] = reg_no

    # saving hash in db
    hashes1 = Hashes(reg_no=reg_no, email=email, hash=hash_key)
    print("Created hash - {}: {}: {}".format(reg_no, email, hash_key))
    db.session.add(hashes1)
    db.session.commit()
    
    return redirect(url_for('verify.verification_sending'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@auth.route('/forgot-password')
def forgot_password():
    print("\nRqeuested 'GET' for the forgot-password form...")
    return render_template('forgot-password.html')
        

@auth.route('/forgot-password', methods=['POST'])
def forgot_password_post():
    print("\nSubmitted 'POST' for the forgot-password form...")
    email = request.form.get('email')
    print("\nEmail recieved as - {}".format(email))
    
    user = User.query.filter_by(email=email).first()
    # need to check if the email exists
    if not user:  # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address was not found in our database. Please check again.')
        return redirect(url_for('auth.forgot_password'))
    
    
    reg_no = user.reg_no
    print("{} has requested a password reset link.".format(reg_no))
    key_user = Hashes.query.filter_by(reg_no=reg_no).first()
    if (key_user==None):
        print("User account is not verified, or not found!")
        return "Your account either doesn't exist, or was not verified!"
    print("The hash should be - {}".format(key_user))
    
    key = key_user.hash
    
    # TODO implement the db model to hold an otp hash, so we could send a dynamic hash for this process
    # better security
    url_to_send = "http://127.0.0.1:5000/reset-password?reg={}&key={}".format(reg_no, key)
    print ("Sending verification email...")
    rendered_page =  render_template('reset-email.html', reset_link=url_to_send)
    service = send_mail.gmail_authenticate()
    reciever_email = "user.ftp.server@gmail.com" # don't hardcode this
    mail_subject = "Password reset link for your DCS-Portal account"

    send_mail.send_message(service, reciever_email, mail_subject, rendered_page)
    
    return render_template('check-email.html')
    

# working
@auth.route('/reset-password', methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        print("A 'GET' request processed for a password reset form!")
        key = request.args.get('key')
        reg_no = request.args.get('reg')
        print("Verifying {} - {}".format(reg_no, key))
        
        try:
            student_to_verify = User.query.filter_by(reg_no=reg_no).first()
            if student_to_verify:
                print("Student found {}".format(student_to_verify.name))
            hash_in_db = Hashes.query.filter_by(reg_no=student_to_verify.reg_no).first()    
            if(key == hash_in_db.hash):
                print("Verification was successful for {}".format(reg_no))
                session['reg_no'] = reg_no  # need to pass the reg_no to the post processing
            else:
                print("Verification failed! : {}".format(key))
                return "Your reset link did not validate!"
        except Exception as e:
            return "Error! {}".format(e)

        return render_template('reset-password.html')
    
    elif request.method == "POST":
        print("A 'POST' submision processed for a password reset form!")
        password = request.form.get('password')
        try:
            if password:
                print("Entered a new password...")
                reg_no = session.pop('reg_no', None)
                if reg_no :
                    print("Reg number got from session - {}".format(reg_no))
                    cur_user = User.query.filter_by(reg_no=reg_no).first()
                    new_password_hash = generate_password_hash(password, method='sha256')
                    cur_user.password = new_password_hash
                    db.session.commit()
                    print("Password updated to - {}".format(new_password_hash))
                    #TODO - send an email after
                    return "Your password was successfully modified!"
                else:
                    print("Reg number getting from session failed!")
            else:
                return "Error!"
        except Exception as e:
            return "Error! {}".format(e)
    
    else:
        print("Something went wrong with the method checking!")
        return "Critical error in server-side"
        