from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify, make_response
import pymysql
from flask_cors import CORS
from datetime import datetime
from datetime import timedelta
import re
import random
import jwt
from functools import wraps
import os
from werkzeug.utils import secure_filename


app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}})

# App confiuration
app.config['SECRET_KEY'] = '25f28838cef544dfabaef370d952ad02'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.png', '.txt']
app.config['UPLOAD_PATH'] = 'uploads'
app.permanent_session_lifetime = timedelta(minutes=10)

conn = pymysql.connect(
        host='localhost',
        user='root', 
        password = "",
        db='RESTFUL_DB',
		cursorclass=pymysql.cursors.DictCursor
        )
cur = conn.cursor()

## Routes ##
@app.route('/')
def index():
    return render_template('index.html')

# Decorator for authentication
def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        print(token)
        if not token:
            return jsonify({'Alert': 'Token is missing.'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print(data)
        except:
            return jsonify({'Error': 'Invalid Token'}), 403
        return func(*args, **kwargs)
    return decorated

# Validate login with SQL DB
def valid_login(username, password):
    print('hi', username)
    cur.execute('SELECT * FROM accounts WHERE username = % s AND password = % s', (username, password, ))
    conn.commit()
    account = cur.fetchone()
    print(account)
    if account:
        msg = 'Logged in successfully !'
        return (True, account, msg)
    else:
        msg = 'Incorrect username / password !'
        account = None
        return (False, account, msg)
    
# Login using front end
@app.route('/login', methods=['GET, POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        validated, account, msg = valid_login(username, password)
        if validated:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            return redirect('home')
    return render_template('login.html')

# API login
@app.route('/api/login', methods = ['POST'])
def api_login():
    msg = ''
    # if request.method == 'GET':
    #     if 'loggedin' in session:
    #         return redirect('home')
    #     return render_template('login.html')
    print(request.json)
    username = request.json.get('username')
    password = request.json.get('password')
    validated, account, msg = valid_login(username, password)
    if validated:
        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = account['username']
        print(account['username'])
        token = jwt.encode({
            'user': account['username'],
            'expiration': str(datetime.utcnow() + timedelta(minutes=60))
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    else:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

# home route
@app.route('/home')
def home():
     if 'loggedin' in session:
        return render_template('home.html')
     else:
        return redirect('login')

# logout route
@app.route('/logout') 
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# sign up using front end
@app.route('/signup', methods =['GET', 'POST'])
def signup():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        id = random.randint(0,10000)
        cur.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cur.fetchone()
        print(account)
        conn.commit()
        if account:
            msg = 'Username already exists!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers.'
        else:
            cur.execute('INSERT INTO accounts VALUES (%s, %s, %s)', (id, username, password))
            conn.commit()
            msg = 'Successfully signed up!'
    elif request.method == 'POST':
            msg = 'Form incomplete!'
    return render_template('signup.html', msg = msg)


# public data for API
public_data = [{'id': 1, 'name': 'Public APIs'},
               {'id': 2, 'name': 'Pricing and Plans'},
               {'id': 3, 'name': 'Developer Documentation'}]

# public route with no auth
@app.route('/public', methods=['GET'])
def public():
    return jsonify(public_data), 200

# protected route 
@app.route('/protected')
@token_required
def protected():
    return jsonify({'message': 'This is a protected endpoint!'})

# uploading files
@app.route('/fileupload', methods=['POST'])
def upload_files():
    upload_file = request.files['file']
    filename = secure_filename(upload_file.filename)
    if filename != "":
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            abort(400)
        upload_file.save(os.path.join(app.config['UPLOAD_PATH'], filename))
        return jsonify({'message': 'File uploaded successfuly'})

# list of all endpoints
@app.route('/endpoints')
def get_endpoints():
    endpoints = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            endpoints.append({
                'url': str(rule),
                'function': app.view_functions[rule.endpoint].__name__
            })
    return jsonify({'endpoints': endpoints})


## Error Handling ##
@app.errorhandler(400)
def bad_request_error(error):
    return render_template('400.html'), 400

@app.errorhandler(401)
def unauthorized(error):
    return render_template('401.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500


if __name__ == "__main__":
	app.run(debug=True)