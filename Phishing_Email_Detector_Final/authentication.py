#Refrences: 
#Blueprint library and functionalities: https://flask.palletsprojects.com/en/stable/blueprints/
#SQLite3: https://docs.python.org/3/library/sqlite3.html#how-to-use-connection-shortcut-methods
#Python Flash: https://flask.palletsprojects.com/en/stable/patterns/flashing/
#Python Session: https://flask.palletsprojects.com/en/stable/quickstart/#redirects-and-errors
#Python redirect: https://flask.palletsprojects.com/en/stable/quickstart/#redirects-and-errors
#Python current_app: https://flask.palletsprojects.com/en/stable/api/#flask.current_app
#Python Bcrypt: https://flask-bcrypt.readthedocs.io/en/1.0.1/


#Imported required libraries to prefrom the functionalities in the authentication.py file 
from flask import Flask, Blueprint, redirect, request, url_for, flash, session, current_app, render_template
#Imported the sqlite3 database library
import sqlite3 

#Intializing the authentication module using the Blueprint sub library 
authentication = Blueprint("authentication", __name__)

#Created a function which handles the functionality of the database 
def __init_sqlDB() :
    #Intialzing the SQL database and called it users.db 
    conn = sqlite3.connect("users.db") 
    cursor = conn.cursor()
    #Created the table within the database which holds the users information upon registering through the application 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstname TEXT NOT NULL,
            lastname TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
#Calling the database function 
__init_sqlDB()

#Created an route for logging into the Phishing Email Detector application 
@authentication.route("/login",methods=["GET","POST"])
# Function which handles all the login functionality 
def login(): 
    #Takes in the requested input imformation from the user 
    if request.method == "POST" :
        #Takes in the users email 
        email = request.form["email"]
        #Takes in the users password 
        password = request.form["password"]
        
        #Connects to the users database in SQLite3
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        #Searches for the user within the database by email and fetches the first matching record if it exsits in the database
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        #Closing connection to the users database 
        conn.close()

        #Verifies if the user and password matches the ones stored in the users database
        if user and current_app.bcrypt.check_password_hash(user[4],password) :
            session["user"] = email
            #If matches and user logs into the application prompt the message indicating the login was sucessful
            flash("Login Sucessful!", "sucess")
            #Redirect the user to the Phishing Email dectector application once login is sucessful 
            return redirect(url_for("detector.index"))
        #If the user enters the wrong email or password then prompt a message to the user
        flash("Invalid email or password", "danger")
    #return values back to the login HTML file 
    return render_template("login.html")

#Created a route for which the user creates an account on the webpage. 
@authentication.route("/create_user",methods=["GET","POST"])
#Created a function called create_user which handles the all functionalities taking in the user information and creating an account
def create_user() :
    if request.method == "POST" :
        #Takes in the users firstname 
        firstname = request.form["firstname"]
        #Takes in the users lastname
        lastname = request.form["lastname"]
        #Takes in the users email 
        email = request.form["email"]
        #Takes in the users password which they created 
        password = request.form["password"]

        #Takes the password the user inputted and uses bcrypt to generate a hashed password 
        hashed_pw = current_app.bcrypt.generate_password_hash(password).decode("utf-8")

        #Calling on the users database 
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor() 

        #First Checking if the user does already exsist in the SQL users database 
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        exsisting_user = cursor.fetchone()

        #If the user already exsists then prompt them that the email they registered with is already used 
        if exsisting_user :
            flash("Email already registered. Please login.", "danger")
            conn.close()
            return redirect(url_for("authentication.login"))
        #If the user does not exsist then insert into the database the firstname, lastname, email, and password into the SQL dabatase
        else :
            cursor.execute(
                "INSERT INTO users (firstname,lastname,email,password) VALUES (?,?,?,?)",
                (firstname,lastname,email,hashed_pw)
            )
        conn.commit()
        conn.close()

        # After the user has created their account flash a message indicating the user account has been created
        flash("Account Created! Please Log in.", "danger")
        #Redirect the user to the login page 
        return redirect(url_for("authentication.login"))
    #Return all values back to the create_user HTML file 
    return render_template("create_user.html")


#Created a route for which if the user were to logout of the application 
@authentication.route("/logout",methods=["GET","POST"])
#Created a function called logout which will handle the functionality when the user exits out of the application 
def logout() :
    session.pop("user", None)
    #After the user logouts of the application flash a message indicating the logout was sucessful 
    flash("Logged out successfully", "info")
    #Redirect the user back to the login page after logging out of the application 
    return redirect(url_for("authentication.login"))

