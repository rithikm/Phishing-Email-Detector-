#Refrences 
#Blueprint library and functionalities: https://flask.palletsprojects.com/en/stable/blueprints/
#Retrieving HTML Form data using Flask: https://www.geeksforgeeks.org/html/retrieving-html-from-data-using-flask/

#Importing the required libraries needed for the Flask backend to function properly 
from flask import Flask, render_template, request, url_for, Blueprint, session
import pickle
import sqlite3
from datetime import datetime


#Initializing the application
detector = Blueprint("detector",__name__)

def __init_sqlRecords() :
    #Intialzing the SQL database and called it users.db 
    conn = sqlite3.connect("records.db") 
    cursor = conn.cursor()
    #Created the table within the database which holds the users information upon registering through the application 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS records(
            record_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email_address TEXT NOT NULL,
            email_text TEXT NOT NULL,
            prediction TEXT NOT NULL,
            legitimate_confidence REAL,
            phishing_confidence REAL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()
#Calling the database function 
__init_sqlRecords()


#Loading in the logistic regression trained model using pickle.load function
with open("lg_model.pkl", "rb") as f :
    model = pickle.load(f)

#Loading in the countvectorizer using pickle.load function 
with open("countvectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

#Intializung the route and using the GET retrieveing the route when the user loads the webpage and POST to submit the results back 
#to the user when the email text has been sent. 
@detector.route("/detector", methods=["GET", "POST"])
def index():

    #Intialized place holders and set them to default values 
    #These default values will be passed to the GET method when the webpage is loaded up.   
    email_text = ""
    label = None
    phishing_conf = None
    legitimate_conf = None

    #Setting the action to None 
    action = None
    #Handles all functionality of the Phishing Email Dectector application
    if request.method == "POST":
        #Retrieving the specific action as either checking or clearing 
        action = request.form.get('action')
        #If the action is checking preform taking user input and processing of the email text and print out the label and confidence scores 
        if action == 'check' :
            #Having the email text being requested from the user to be taken in by the POST method using the request.form method
            email_text = request.form["email_text"]

            # Preprocessing and Vectorizing the email text being taken in 
            email_vectorized = vectorizer.transform([email_text])

             # Now having the trained model make a prediction based on the preprocessed and vectorized email text 
            predict_label = model.predict(email_vectorized)
            #Labels either Phishing (1) or Legitimate (0) 
            label = "Phishing" if predict_label[0] == 1 else "Legitimate"

            # Preforms the confidence score probability prediction based on the email text 
            probabilities = model.predict_proba(email_vectorized)
            #Calculates and rounds the precentage score to be outputted to the user and by 2 decimal places. 
            legitimate_conf = round(probabilities[0][0] * 100, 2)
            phishing_conf = round(probabilities[0][1] * 100, 2)

            #Checks if the user is already is logged into their account and in a current session
            if "user" in session:
                user_email = session["user"]

                #Connects to the users database to retrieves the users correspodning user id 
                conn_users = sqlite3.connect("users.db")
                cursor_users = conn_users.cursor()
                cursor_users.execute("SELECT id FROM users WHERE email = ?", (user_email,))
                user = cursor_users.fetchone()
                conn_users.close()

                # After the user id has been retrieved it would indicate a time stamp at which the prediction made 
                if user:
                    user_id = user[0]
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Connecting the the records database which would insert the record information of the prediction and the results to be stored 
                    # inside the database. 
                    conn_records = sqlite3.connect("records.db")
                    cursor_records = conn_records.cursor()
                    cursor_records.execute("""
                        INSERT INTO records (user_id, email_address, email_text, prediction,
                                             legitimate_confidence, phishing_confidence, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (user_id, user_email, email_text, label,
                          legitimate_conf, phishing_conf, timestamp))
                    conn_records.commit()
                    conn_records.close()



    #If the action is clear reset all the values back to the default values 
    elif action == 'clear' :
        email_text = ""
        label = None
        phishing_conf = None
        legitimate_conf = None


    #Returning the required information to the index HTML file 
    return render_template(
        "index.html",
        email_text=email_text,
        prediction=label,
        legitimate_confidence=legitimate_conf,
        phishing_confidence=phishing_conf

    )

#Created a route to the Prediction History webpage and called the route history 
@detector.route("/history")
def history():
    #If the user is not logged into a current session or the user is unauthorized redirect the user to the login page 
    if "user" not in session:
        return redirect(url_for("authentication.login"))

    #Retrieves the logged in users email address
    user_email = session["user"]

    # Connects to the users database to retrieve the logged in users id 
    conn_users = sqlite3.connect("users.db")
    cursor_users = conn_users.cursor()
    cursor_users.execute("SELECT id FROM users WHERE email = ?", (user_email,))
    user = cursor_users.fetchone()
    conn_users.close()

    #If conditional created to which if an error occurs during the active session or the session becomes invalid to redirect the user back to the login page 
    if not user:
        return redirect(url_for("authentication.login"))

    user_id = user[0]

    #Connects to the records database to fetch the stored prediction and results infromation from the records database. 
    conn_records = sqlite3.connect("records.db")
    cursor_records = conn_records.cursor()
    cursor_records.execute("SELECT email_text, prediction, legitimate_confidence, phishing_confidence, timestamp FROM records WHERE user_id = ?", (user_id,))
    records = cursor_records.fetchall()
    conn_records.close()

    #Returning the required information to the HTML file
    return render_template("history.html", records=records)