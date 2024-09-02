---
title:  "BLACK HAT MEA CTF QUALS 2024 WEB CHALLENGES WRITEUP"
description: WEB WRITEUP FOR BLACK HAT QUALS 2024
image: 
  path: /assets/img/blog/blackhat/wolv_black_hat.jpg
tags: [ctf,sql_injection,web,Object_Injection]
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

![alt text](<../assets/img/blog/blackhat/watermelone/INJECT.png>)

Then get the file id :
![alt text](<../assets/img/blog/blackhat/watermelone/ID.png>)

Then get the file content:
![alt text](<../assets/img/blog/blackhat/watermelone/READ.png>)

WE GET THE ADMIN PASSWORD, LETS LOGIN AS ADMIN AND GET THE FLAG
![alt text](<../assets/img/blog/blackhat/watermelone/FLAG.png>)




## 2. Notey

### Description
```
I created a note sharing website for everyone to talk to themselves secretly. Don't try to access others notes, grass isn't greener :'( )
```

### Source Code
index.js:
```js
const express = require('express');
const bodyParser = require('body-parser');
const crypto=require('crypto');
var session = require('express-session');
const db = require('./database');
const middleware = require('./middlewares');

const app = express();


app.use(bodyParser.urlencoded({
extended: true
}))

app.use(session({
    secret: crypto.randomBytes(32).toString("hex"),
    resave: true,
    saveUninitialized: true
}));



app.get('/',(req,res)=>{
    res.send("Welcome")
})

app.get('/profile', middleware.auth, (req, res) => {
    const username = req.session.username;

    db.getNotesByUsername(username, (err, notes) => {
    if (err) {
        return res.status(500).json({ error: 'Internal Server Error' });
    }   
    res.json(notes);
    });
});

app.get('/viewNote', middleware.auth, (req, res) => {
    const { note_id,note_secret } = req.query;

    if (note_id && note_secret){
        db.getNoteById(note_id, note_secret, (err, notes) => {
            if (err) {
            return res.status(500).json({ error: 'Internal Server Error' });
            }
            return res.json(notes);
        });
    }
    else
    {
        return res.status(400).json({"Error":"Missing required data"});
    }
});


app.post('/addNote', middleware.auth, middleware.addNote, (req, res) => {
    const { content, note_secret } = req.body;
        db.addNote(req.session.username, content, note_secret, (err, results) => {
            if (err) {
            return res.status(500).json({ error: 'Internal Server Error' });
            }
    
            if (results) {
            return res.json({ message: 'Note added successful' });
            } else {
            return res.status(409).json({ error: 'Something went wrong' });
            }
        });
});


app.post('/login', middleware.login, (req, res) => {
const { username, password } = req.body;

    db.login_user(username, password, (err, results) => {
        if (err) {
        console.log("req ",req.session);
        console.log(err);
        return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length > 0) {
        console.log("sec",req.session);
        req.session.username = username;
        return res.json({ message: 'Login successful' });
        } else {
        console.log(req.session);
        return res.status(401).json({ error: 'Invalid username or password' });
        }
    });
}); 

app.post('/register', middleware.login, (req, res) => {
const { username, password } = req.body;

    db.register_user(username, password, (err, results) => {
        if (err) {
        return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results) {
        return res.json({ message: 'Registration successful' });
        } else {
        console.log(req.session);
        return res.status(409).json({ error: 'Username already exists' });
        }
    });
});

db.wait().then(() => {
    db.insertAdminUserOnce((err, results) => {
        if (err) {
            console.error('Error:', err);
        } else {
            db.insertAdminNoteOnce((err, results) => {
                if (err) {
                    console.error('Error:', err);
                } else {
                    app.listen(3000, () => {
                        console.log('Server started on http://localhost:3000');
                    });
                }
            });
        }
    });
});
```

middlewares.js:
```js
const auth = (req, res, next) => {
    ssn = req.session
    console.log(ssn)
    if (ssn.username) {
        return next();
    } else {
        return res.status(401).send('Authentication required.');
    }
};


const login = (req,res,next) =>{
    const {username,password} = req.body;
    if ( !username || ! password )
    {
        return res.status(400).send("Please fill all fields");
    }
    else if(typeof username !== "string" || typeof password !== "string")
    {
        return res.status(400).send("Wrong data format");
    }
    next();
}

const addNote = (req,res,next) =>{
    const { content, note_secret } = req.body;
    if ( !content || ! note_secret )
    {
        return res.status(400).send("Please fill all fields");
    }
    else if(typeof content !== "string" || typeof note_secret !== "string")
    {
        return res.status(400).send("Wrong data format");
    }
    else if( !(content.length > 0 && content.length < 255) ||  !( note_secret.length >=8 && note_secret.length < 255) )
    {
        return res.status(400).send("Wrong data length");
    }
    next();
}

module.exports ={
    auth, login, addNote
};
```
database.js:
```js
const mysql = require('mysql');
const crypto=require('crypto');


const pool = mysql.createPool({
  host: '127.0.0.1',
  user: 'root',
  password: '',
  database: 'CTF',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// One liner to wait a second
async function wait() {
  await new Promise(r => setTimeout(r, 1000));
}

function insertAdminUserOnce(callback) {
  const checkUserQuery = 'SELECT COUNT(*) AS count FROM users WHERE username = ?';
  const insertUserQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
  const username = 'admin';
  const password = crypto.randomBytes(32).toString("hex");

  pool.query(checkUserQuery, [username], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      callback(err, null);
      return;
    }

    const userCount = results[0].count;

    if (userCount === 0) {
      pool.query(insertUserQuery, [username, password], (err, results) => {
        if (err) {
          console.error('Error executing query:', err);
          callback(err, null);
          return;
        }
        console.log(`Admin user inserted successfully with this passwored ${password}.`);
        callback(null, results);
      });
    } else {
      console.log('Admin user already exists. No insertion needed.');
      callback(null, null);
    }
  });
}

function insertAdminNoteOnce(callback) {
  const checkNoteQuery = 'SELECT COUNT(*) AS count FROM notes WHERE username = "admin"';
  const insertNoteQuery = 'INSERT INTO notes(username,note,secret)values(?,?,?)';
  const flag = process.env.DYN_FLAG || "placeholder";
  const secret = crypto.randomBytes(32).toString("hex");

  pool.query(checkNoteQuery, [], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      callback(err, null);
      return;
    }

    const NoteCount = results[0].count;

    if (NoteCount === 0) {
      pool.query(insertNoteQuery, ["admin", flag, secret], (err, results) => {
        if (err) {
          console.error('Error executing query:', err);
          callback(err, null);
          return;
        }
        console.log(`Admin Note inserted successfully with this secret ${secret}`);
        callback(null, results);
      });
    } else {
      console.log('Admin Note already exists. No insertion needed.');
      callback(null, null);
    }
  });
}


function login_user(username,password,callback){

  const query = 'Select * from users where username = ? and password = ?';
  
  pool.query(query, [username,password], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      callback(err, null);
      return;
    }
    callback(null, results);
  });
}

function register_user(username, password, callback) {
  const checkUserQuery = 'SELECT COUNT(*) AS count FROM users WHERE username = ?';
  const insertUserQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';

  pool.query(checkUserQuery, [username], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      callback(err, null);
      return;
    }

    const userCount = results[0].count;

    if (userCount === 0) {
      pool.query(insertUserQuery, [username, password], (err, results) => {
        if (err) {
          console.error('Error executing query:', err);
          callback(err, null);
          return;
        }
        console.log('User registered successfully.');
        callback(null, results);
      });
    } else {
      console.log('Username already exists.');
      callback(null, null);
    }
  });
}


function getNotesByUsername(username, callback) {
  const query = 'SELECT note_id,username,note FROM notes WHERE username = ?';
  pool.query(query, [username], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      callback(err, null);
      return;
    }
    callback(null, results);
  });
}

function getNoteById(noteId, secret, callback) {
  const query = 'SELECT note_id,username,note FROM notes WHERE note_id = ? and secret = ?';
  console.log(noteId,secret);
  pool.query(query, [noteId,secret], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      callback(err, null);
      return;
    }
    callback(null, results);
  });
}

function addNote(username, content, secret, callback) {
  const query = 'Insert into notes(username,secret,note)values(?,?,?)';
  pool.query(query, [username, secret, content], (err, results) => {
    if (err) {
      console.error('Error executing query:', err);
      callback(err, null);
      return;
    }
    callback(null, results);
  });
}


module.exports = {
  getNotesByUsername, login_user, register_user, getNoteById, addNote, wait, insertAdminNoteOnce, insertAdminUserOnce
};
```

From the function `insertAdminNoteOnce` in database.js, we can see that the flag is stored in the database with the username `admin` and a random secret. The flag is stored in the `note` column, so to get the flag, we need to get the note with the username `admin` and `id` which is not known to us and the secret which is random.

and to get any note there is two ways to get the note by the `note_id` and `note_secret` which can be done by the endpoint `/viewNote` or by the username and which can be done by the endpoint `/profile`.

Also There is no Frontend for the challenge so we have to use curl or burp to interact with the challenge.

### Solution:

#### THE SECRET BEHIND 66
this challenge really blew my mind, I spent a lot of time trying to find a way to get the flag, but I couldn't find a way to get the secret, so I decided to look at the `init.db` file and I found out that the `id` column is auto increment but starts from 66, so the admin note id is 66.

![alt text](<../assets/img/blog/blackhat/notey/initdb.png>)

so that restricted my idea to get the flag by the `note_id` and `note_secret` using the endpoint `/viewNote`, but I couldn't find a way to get the secret as it's random.

### Short explanation of the exploit:
- The `note_id` is known to be 66
- The `note_secret` is random
- we can inject an object in the `note_secret` field to get the flag

`/viewNote?note_id=66&note_secret[note_id]=0`


the `note_secret` is an object that contains the key `note_id` with the value 0 so the query will be like this `SELECT note_id,username,note FROM notes WHERE note_id = 66 and secret = \`note_id\` = '0'`

Here's a breakdown of what happens:

  note_id = 66: This condition is straightforward and will select rows where note_id is equal to 66.

  secret = \`note_id\` = '0': This part is more complex and involves a bit of SQL logic.

  SQL evaluates expressions from left to right. So, the expression `secret = \`note_id\` = '0'` is interpreted as (secret = \`note_id\` ) = '0'.

  The expression `secret = \`note_id\` will return a boolean value (1 for true, 0 for false) depending on whether the value of secret is equal to the string 'note_id', in our case it will return 0 as the secret is not equal to \`note_id\`.

  The result of secret = \`note_id\` (which is either 1 or 0 but in our case it will return 0 as the note id is 66 and the secret is 32 random length) is then compared to '0'.

  Since '0' is a string and 1 or 0 are integers, the comparison will treat '0' as an integer. So, the expression (secret = \`note_id\`) = '0' will check if the result of secret = \`note_id\` is equal to the integer 0.

  so, the condition (secret = \`note_id\`) = '0' is now `0=0`

  Therefore, the query will select rows where note_id is 66 and `0=0`. This will return the flag.

Here in this image is a similar example to understand the output:
![alt text](<../assets/img/blog/blackhat/notey/online.png>)
then it became:
![alt text](<../assets/img/blog/blackhat/notey/on2.png>)

Also here is the request from mysql logs to be sure of how our request interpreted by the database
![alt text](<../assets/img/blog/blackhat/notey/local.png>)

### Getting the flag
we need to be fast when getting the flag as the server was restarting every few seconds, so we need to write a script to get the flag as soon as the server starts.

```python
from requests import Session

s = Session()
login_url = "http://a233af04b075fbec51200.playat.flagyard.com/login"
note_url = "http://a233af04b075fbec51200.playat.flagyard.com/viewNote"
creds = {"username": "logan0x", "password": "logan0x"}
note_params = {"note_id": 66, "note_secret[note_id]": 0}
print(s.get(note_url, params=note_params).text)
```


### Long explanation of the exploit:

for Long explanation of the issue reason you can check this [https://gccybermonks.com/posts/obji2sqli/](https://gccybermonks.com/posts/obji2sqli/)

