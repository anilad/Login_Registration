from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re, md5, os, binascii

app = Flask(__name__)
app.secret_key = 'keepitsecretkeepitsafe'
mysql = MySQLConnector(app,'usersdb')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r"^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$")

@app.route('/')
def index():
    if not 'id' in session:
        session['id'] = None
    query = "SELECT * FROM users"
    users = mysql.query_db(query) 
    return render_template('index.html', users=users)

@app.route('/users')
def users():
    # insert code for use on /users
    return render_template('users.html')

@app.route('/login', methods=['POST'])
def login():
    eMail = request.form['email']
    if EMAIL_REGEX.match(eMail):
        query = "SELECT email, password, salt FROM users WHERE email = :email"
        data = {
            'email': eMail
        }
        users = mysql.query_db(query,data)
        # validEmail = False
        validPassword = False

        # if there are no registered users
        if not users:
            flash('There are no users with this email, please enter a valid email')
            return redirect('/')
        else:
             # check if client input email and password match items in database. USE md5 and salt to hash pw input for verification with db
    
            if users[0]['password'] == md5.new(request.form['password'] + users[0]['salt']).hexdigest():
                validPassword=True
            
            if validPassword == True:
                return redirect('/users')
    flash('Incorrect email or password')
    return redirect('/')

@app.route('/register')
def register():
    return render_template('registration.html')

@app.route('/process', methods=['POST'])
def process():
    isValid=False
    #check for valid input in fName (cannot be blank)
    if len(request.form['fName'])<1:
        flash('First Name cannot be blank!')
        isValid = True
    #check for valid input in fName (includes only letters)
    elif not NAME_REGEX.match(request.form['fName']):
        flash("Invalid Name! Name cannot include numbers or special characters.")
        isValid=True
    #name is valid input
    else:
        fName = request.form['fName']

    #check for valid input in lName (cannot be blank)
    if len(request.form['fName'])<1:
        flash('Last Name cannot be blank!')
        isValid = True
    #check for valid input in lName (includes only letters)
    elif not NAME_REGEX.match(request.form['lName']):
        flash("Invalid Name! Name cannot include numbers or special characters.")
        isValid=True
    #name is valid input
    else:
        lName = request.form['lName']

    #check for valid input in email (must be valid email)
    if len(request.form['email']) < 1:
        flash("Email cannot be blank!")
        isValid = True
    #check for valid input in email (email must follow standard format)
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!")
        isValid = True
    #email is valid input
    else:
        email=request.form['email']

    #check for valid input in password(must be 8+ characters and  contain upper and lowercase letters and numbers)
    if not PASSWORD_REGEX.match(request.form['password']):
        flash('Password invalid! Password needs at least 8 characters, 1 uppercase, 1 number, 1 special character')
        isValid=True

    #check if password comfirmation matches password input
    if not request.form['confirm'] == request.form['password']:
        flash('Password confirmation does not match Password!')
        isValid=True
    # if confirmation matches password, hash password with salt
    else:
        password = request.form['password']
        salt =  binascii.b2a_hex(os.urandom(15))
        hashPass = md5.new(password + salt).hexdigest()
    
    #user input did not fully pass validation
    if isValid:
        return redirect('/')     
    #user input fully passed validation, insert valid user registration info into usersdb   
    else: 
        insert_query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, :salt, NOW(), NOW())"

        query_data = { 'first_name': fName, 'last_name': lName, 'email': email, 'password': hashPass, 'salt': salt}

        mysql.query_db(insert_query, query_data)
        
        session['id']= mysql.query_db(insert_query, query_data)

        return redirect('/users')
    
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('id')
    return redirect('/')
app.run(debug=True)
    