import sqlite3
connection = sqlite3.connect("Login.db")

cursor = connection.cursor()



# delete 


sql_command = """
CREATE TABLE users ( 
id INTEGER PRIMARY KEY, 
nam VARCHAR(20), 
psw VARCHAR(20),
salt VARCHAR(20),
joining DATE
);"""



sql_command = """INSERT INTO users (id, nam, psw)
    VALUES (NULL, 'Fisch', 'Dumisel');"""
sql_command = """DROP TABLE users"""
cursor.execute(sql_command)

exe='''CREATE TABLE users (
    user_id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    psw VARCHAR (255) NOT NULL,
    salt VARCHAR (255) NOT NULL,
    joining_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);'''
cursor.execute(exe)

exe2='''CREATE TABLE Messages (
    message_id INTEGER PRIMARY KEY ,
    sender_id INT,
    recipient_id INT,
    message_text TEXT,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    AES_Code TEXT,
    LWE_Code TEXT,
    FOREIGN KEY (sender_id) REFERENCES Users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES Users(user_id) ON DELETE CASCADE
);'''

#cursor.execute(exe2)
exe6='''INSERT INTO Messages (sender_id,recipient_id,message_text) VALUES (2,1,'Hallo')'''
#cursor.execute(exe6)

# never forget this for saving
connection.commit()
exe3='''SELECT * FROM users'''
cursor.execute(exe3)
print(cursor.fetchall())
exe4= '''SELECT * FROM Messages'''
cursor.execute(exe4)
print(cursor.fetchall())
connection.close()
'''connection = sqlite3.connect("company.db")

cursor = connection.cursor()

staff_data = [ ("William", "Shakespeare", "m", "1961-10-25"),
               ("Frank", "Schiller", "m", "1955-08-17"),
               ("Jane", "Wall", "f", "1989-03-14") ]
               
for p in staff_data:
    format_str = """INSERT INTO employee (staff_number, fname, lname, gender, birth_date)
    VALUES (NULL, "{first}", "{last}", "{gender}", "{birthdate}");"""

    sql_command = format_str.format(first=p[0], last=p[1], gender=p[2], birthdate = p[3])
    cursor.execute(sql_command)'''


