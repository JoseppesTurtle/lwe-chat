from flask import Flask, request, render_template, redirect, url_for, render_template_string
from flask_socketio import SocketIO, send, join_room, leave_room
import sqlite3
import bcrypt
import gevent
from hashlib import sha256

connection = sqlite3.connect('Login.db')

cursor = connection.cursor()

cursor.execute("SELECT psw FROM users ")
passwords = cursor.fetchall()
passwords = list(filter(None, ''.join(str(value).strip('(,)') for value in passwords).split("'")))
print(passwords)

cursor.execute("SELECT username FROM users")
users = cursor.fetchall()
users = list(filter(None, ''.join(str(value).strip('(,)') for value in users).split("'")))
print (users)



connection.close()

def new_user(username, password,salt):
    global users, passwords
    connection = sqlite3.connect('Login.db')
    cursor = connection.cursor()
    register ="INSERT INTO users (username,psw,salt) values (?, ?,?)"
    cursor.execute(register,(username,password,salt))

    connection.commit()
    connection.close()
    

def searchuser(user,password):
    connection = sqlite3.connect('Login.db')
    cursor = connection.cursor()
    search = 'SELECT psw FROM users WHERE username = ?'
    cursor.execute (search,(user,))
    psw = cursor.fetchone()
    search = 'SELECT salt FROM users WHERE username = ?'
    cursor.execute (search,(user,))
    salt = cursor.fetchone()
    connection.close()
    if psw[0] == bcrypt.hashpw(password.encode(), salt[0]):
        return True
    else:
        return False
    
def checkuser(newuser):
    connection = sqlite3.connect('Login.db')
    cursor = connection.cursor()
    search = 'SELECT 1 FROM users WHERE username = ?'
    cursor.execute (search,(newuser,))
    a=cursor.fetchone()
    connection.close()
    if a==None:
        return True
    else:
        return False

def get_id(username):
    connection = sqlite3.connect('Login.db')
    cursor = connection.cursor()
    search = 'SELECT user_id FROM users WHERE username = ?'
    cursor.execute (search,(username,))
    a=cursor.fetchone()
    connection.close()

app = Flask(__name__)

socketio = SocketIO(app, async_mode='gevent')


#MESSAGE
@socketio.on('message')
def handlemessage (message,data,username,targetId):
    if message=='join':
        room=username
        join_room(room)
        pk=targetId
        print(type(pk))
        send(f"00000000101_{username} has entered the room.", to=room)
    elif message=='request':
        send(f"{username}", to=targetId)
    elif message=='pk':
        print(type(data))
        send(data, to=targetId)
    elif message=='c':
        send(data,to=targetId)
    else:
        send(f"{data}", to=targetId)



@app.route('/login/Chatroom/<name>')
def index(name):
    return render_template('index.html',name=name)

@app.route('/')
def home():
    return redirect('/login')

#Login
@app.route('/login', methods=['GET'])
def Login():
    global username
    newuser = request.args.get('nnam')
    user = request.args.get('nam')
    newpassword = request.args.get('npsw')
    password = request.args.get('psw')
    
    if user is None and newuser is None: 
        
        return render_template('Login.html')
    elif user is None:
        
        if newuser.strip() == '' or newpassword.strip() == '':
            return render_template_string('''
        <p>Please Enter a username and password</p>
        <a href="https://lwe-chat.onrender.com">Go back</a>
    ''')
        else:
            if newuser is None or newpassword is None:
                pass
            elif checkuser(newuser):
                salt=bcrypt.gensalt()
                hash=bcrypt.hashpw(newpassword.encode(), salt)
                new_user(newuser,hash,salt)
                return render_template_string('''<h1>great</h1><a href="https://lwe-chat.onrender.com">Go back</a>
    ''')
            else:
                return render_template_string('''<h1>Username exists</h1><a href="https://lwe-chat.onrender.com">Go back</a>
    ''')
    else:
        if user.strip() == '' or password.strip() == '': 
            return render_template_string('''<h1>Empty Input!</h1><a href="https://lwe-chat.onrender.com">Go back</a>
    ''')
        elif checkuser(newuser):
            return render_template_string('''<h1>User doesn't exist</h1><a href="https://lwe-chat.onrender.com">Go back</a>
    ''')
        else:
            if searchuser(user, password):
                return redirect(url_for('index', name=user)) 
            else:
                return render_template_string('''<h1>Incorrect Username or Password</h1><a href="https://lwe-chat.onrender.com">Go back</a>
    ''')
    
@socketio.on_error()
def error_handler(e):
    print('SocketIO error:', str(e))  
    

if __name__ == '__main__':
    socketio.run(app, debug=True, port=8000)