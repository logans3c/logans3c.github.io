---
title:  "ICMTC 2024 FINALS WEB CHALLENGES WRITEUP"
description: WEB WRITEUP FOR ICMTC CTF
image: 
  path: /assets/img/blog/icmtc.jpg
tags: [ctf,sql_injection,prisma,orm_injection,web]
date:   2024-07-28 13:49:56 +0300
categories: [CTFs]
---
Hi I am Mohammed Ashraf AKA logan0x
and this is my Writeup for BlackHat Mea Web Challenges

## 1. Watermelon
### Description
```
All love for Watermelons 🍉🍉🍉

Note: The code provided is without jailing, please note that when writing exploits.
```

### Source Code
```python
from flask import Flask, request, jsonify, session, send_file
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import os, secrets
from werkzeug.utils import secure_filename



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(20)
app.config['UPLOAD_FOLDER'] = 'files'


db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('files', lazy=True))


def create_admin_user():
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(username='admin', password= secrets.token_hex(20))
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created.")
    else:
        print("Admin user already exists.")

with app.app_context():
    db.create_all()
    create_admin_user()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or 'user_id' not in session:
            return jsonify({"Error": "Unauthorized access"}), 401
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or 'user_id' not in session or not session['username']=='admin':
            return jsonify({"Error": "Unauthorized access"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return 'Welcome to my file sharing API'

@app.post("/register")
def register():
    if not request.json or not "username" in request.json or not "password" in request.json:
        return jsonify({"Error": "Please fill all fields"}), 400
    
    username = request.json['username']
    password = request.json['password']

    if User.query.filter_by(username=username).first():
        return jsonify({"Error": "Username already exists"}), 409

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"Message": "User registered successfully"}), 201

@app.post("/login")
def login():
    if not request.json or not "username" in request.json or not "password" in request.json:
        return jsonify({"Error": "Please fill all fields"}), 400
    
    username = request.json['username']
    password = request.json['password']

    user = User.query.filter_by(username=username, password=password).first()
    if not user:
        return jsonify({"Error": "Invalid username or password"}), 401
    
    session['user_id'] = user.id
    session['username'] = user.username
    return jsonify({"Message": "Login successful"}), 200

@app.get('/profile')
@login_required
def profile():
    return jsonify({"username": session['username'], "user_id": session['user_id']})

@app.get('/files')
@login_required
def list_files():
    user_id = session.get('user_id')
    files = File.query.filter_by(user_id=user_id).all()
    file_list = [{"id": file.id, "filename": file.filename, "filepath": file.filepath, "uploaded_at": file.uploaded_at} for file in files]
    return jsonify({"files": file_list}), 200


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"Error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"Error": "No selected file"}), 400
    
    user_id = session.get('user_id')
    if file:
        blocked = ["proc", "self", "environ", "env"]
        filename = file.filename

        if filename in blocked:
            return jsonify({"Error":"Why?"})

        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
        os.makedirs(user_dir, exist_ok=True)
        

        file_path = os.path.join(user_dir, filename)

        file.save(f"{user_dir}/{secure_filename(filename)}")
        

        new_file = File(filename=secure_filename(filename), filepath=file_path, user_id=user_id)
        db.session.add(new_file)
        db.session.commit()
        
        return jsonify({"Message": "File uploaded successfully", "file_path": file_path}), 201

    return jsonify({"Error": "File upload failed"}), 500

@app.route("/file/<int:file_id>", methods=["GET"])
@login_required  
def view_file(file_id):
    user_id = session.get('user_id')
    file = File.query.filter_by(id=file_id, user_id=user_id).first()

    if file is None:
        return jsonify({"Error": "File not found or unauthorized access"}), 404
    
    try:
        return send_file(file.filepath, as_attachment=True)
    except Exception as e:
        return jsonify({"Error": str(e)}), 500


@app.get('/admin')
@admin_required
def admin():
    return os.getenv("FLAG","BHFlagY{testing_flag}")



if __name__ == '__main__':
    app.run(host='0.0.0.0')
```

### Solution

The challenge is a simple lfd vulnertability because of file upload function weakness. Also the challenge does not have any ui so we have to use curl of burp to interact with the challenge.

Here is the interesting code snippet
```python
@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"Error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"Error": "No selected file"}), 400
    
    user_id = session.get('user_id')
    if file:
        blocked = ["proc", "self", "environ", "env"]
        filename = file.filename

        if filename in blocked:
            return jsonify({"Error":"Why?"})

        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
        os.makedirs(user_dir, exist_ok=True)
        

        file_path = os.path.join(user_dir, filename)

        file.save(f"{user_dir}/{secure_filename(filename)}")
        

        new_file = File(filename=secure_filename(filename), filepath=file_path, user_id=user_id)
        db.session.add(new_file)
        db.session.commit()
        
        return jsonify({"Message": "File uploaded successfully", "file_path": file_path}), 201

    return jsonify({"Error": "File upload failed"}), 500
```

1. Insufficient Filename Validation:
  - code checks the filename against a list of blocked keywords (`blocked = ["proc", "self", "environ", "env"]`), but this check is too simplistic

2. Improper use of secure_filename():

  - The code uses secure_filename() when saving the file, but not when constructing the file_path, but not when constructing the file_path
  ```python 
  file_path = os.path.join(user_dir, filename)
file.save(f"{user_dir}/{secure_filename(filename)}")
```
  
  - The function `secure_filename()` is used to sanitize the filename, for example it removers the `../` from file name
  
  ```python

  from werkzeug.utils import secure_filename

filename = "../../../etc/passwd"
safe_filename = secure_filename(filename)
print(safe_filename) //etc_passwd
```

3. Improper use of os.path.join():

  - The code uses os.path.join() to construct the file_path `file_path = os.path.join(user_dir, filename)` but it does not sanitize the filename, so if we upload a file with a filename like `/etc/passwd`, file_path will be `/etc/passwd`.
  
  Here is a small snippet to understand the issue
```python

import os

user_dir = "/home/user/uploads"
filename = "/app/db.db"

file_path = os.path.join(user_dir, filename)
print(file_path) #/app/db.db
```

4. Saving the file path in the database differ from the actual file path:

  - The code saves the file in the server using this line `file.save(f"{user_dir}/{secure_filename(filename)}")` so if the we set the file name to be `/etc/passwd` the `file_path` variable will be `/etc/passwd` but when the when this passed to `secure_filename` it will be `etc_passwd` so we will not override any files.

  - The code saves the file path in the database using this line `new_file = File(filename=secure_filename(filename), filepath=file_path, user_id=user_id)`, so the file path in the database will be our the file_path variable without any modification by `secure_filename` function.


#### Exploitation:
To exploit this, we could:

- Upload a file with a name like "/etc/passwd"
- The file would be saved safely due to secure_filename(), but the path in the database would contain the malicious path.
- in a subsequent request to the endpoint `/file/<int:file_id>` which sends us the file based on the `file_path` in the database, it will return the content of the file `/etc/passwd` because the file path in the database is `/etc/passwd` and the file is saved in the server with the name `etc_passwd`

![alt text](<Screenshot 2024-09-01 161051.png>)

Then get the file id :
![alt text](<Screenshot 2024-09-01 161102.png>)

Then get the file content:
![alt text](<Screenshot 2024-09-01 161109.png>)

WE GET THE ADMIN PASSWORD, LETS LOGIN AS ADMIN AND GET THE FLAG
![alt text](<Screenshot 2024-09-01 161043.png>)







