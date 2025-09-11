from flask import Flask, request, render_template, render_template_string, redirect, session, CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from os import getenv
import sqlite3
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = getenv("DATABASE_URL")
app.secret_key = "iuwoeh0230"
database = "users.db"
#FIX FOR FLAW 3
#csrf = CSRFProtect(app)

if not os.path.exists(database):
    connect = sqlite3.connect(database)
    db = connect.cursor()
    db.execute("DROP TABLE IF EXISTS users")
    db.execute("""CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, balance REAL, account_number TEXT)""")
    db.execute("""INSERT INTO users (username, password) VALUES ("admin", "admin_ok")""")
    #A07:2021 Identification and Autehtication Failures
    #Fix: hashed_password = generate_password_hash("admin_ok")
    #db.execute("""INSERT INTO users (username, password, balance, account_number) VALUES (?, ?, ?, ?)""", ("admin", "hashed_password", 500, 1234ACCOUNT))
    connect.commit()
    connect.close()

@app.route("/")
def index():
    return """Hello<br>
    <li><a href="/login">Login</a></li>
    <li><a href="/adminpage">Admin page</a></li>
    
    """


#A03:2021 - Injection
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        connect = sqlite3.connect(database)
        db = connect.cursor()
        db.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}' ")
        #The sql command is vulnerable. Could be accessed with statement that is always true.
        #Fixed sql: db.execute("""SELECT * FROM users WHERE username = ? AND password = ? """, (username, password))
        ### 
        #Fixed A07:2021: r = db.fetchone()
        #if r and check_password_hash(r[0], password):
            #session["user"] = username
            #return redirect("/adminpage")
        user = db.fetchone()
        connect.close()
        if user:
            session["user"] = username
            return redirect("/adminpage")
        
    return render_template("index.html")

#A01:2021 - Broken Access Control
@app.route("/adminpage")
def adminpage():
    print("Session contents:", session)
    if "user" in session: #Does not check the status of the user
    #Fixed with checking if the user is an admin:
    #if "user" in session and session["user"] == "admin":
        connect = sqlite3.connect(database)
        db = connect.cursor()
        db.execute("SELECT username, balance, account_number FROM users")
        users = db.fetchall()
        connect.close()
        info = "<h2> data </h2><table border="1"><tr><th>username</th><th>balance</th><th>account number</th></tr>"
        for username, balance, account_number in users:
            info += f"<tr><td>{username}</td><td>{balance}</td><td>{account_number}</td></tr>"
        info += "</table><hr>"
        
        return f"""Hello world and especially {session["user"]}
        <form action="/moneytransfer" method="post">
        <p>Transfer money cause why not?</p>
        To: <input name="to"><br>
        Amount: <input name="amount" type="number"><br>
        <input type="submit" value="Make the transfer">
        </form>
        """ 
    return redirect("/login")
    

#CSRF token missing
@app.route("/change_password", methods=["POST"])
def change_password():
    new_p = request.form["password"]
    if "user" not in session:
        return redirect("/login")
    connect = sqlite3.connect(database)
    db = connect.cursor()
    db.execute("""UPDATE users SET password = ? WHERE username = ?""", (new_p, session["user"]))
    connect.commit()
    return "Yay it worked!"

#A04:2021 - Insecure design
@app.route("/moneytransfer", methods=["POST"])
def moneytransfer():
    send = session.get("user")
    rec = request.form["to"]
    amount = float(request.form["amount"])
    return f"Money transfered {amount:.2f} euros from {send} to {rec}"
    #Fix:
    #if not rec or amount <= 0:
        #return "Sorry doesn't work"
    #if send not in authorized_users:
        #return "Sorry I don't trust you"
    

if __name__ == "__main__":
    app.run(debug=True) #A08:2021 - Security Misconfiguration
    #Fixed with app.run(debug=False)

    
