from flask import Flask, redirect, url_for
from authentication import authentication
from detector import detector
from flask_bcrypt import Bcrypt
import key

app = Flask(__name__)
#This is utilized if session sub library is being utilized in which it keeps track of all the auhentication routes being made
app.secret_key = key.SECRET_KEY

# Initialize bcrypt to preform the password functionality on all blueprints. 
#Refrence: https://flask-bcrypt.readthedocs.io/en/1.0.1/
app.bcrypt = Bcrypt(app)


# Register blueprints and mounts them within the main app.py file 
#Refrence: https://flask.palletsprojects.com/en/stable/blueprints/
app.register_blueprint(authentication, url_prefix="/auth")  
app.register_blueprint(detector, url_prefix="/detector")   

# Created the main app route 
@app.route("/")
#Created a function called default which directs the user to the login page when running the application 
def default():
    return redirect(url_for("authentication.login"))

#Using the app.run() command which allows to run the application.
if __name__ == "__main__":
    app.run(debug=True)


