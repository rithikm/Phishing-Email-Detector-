#Importing the required libraries needed for the Flask backend to function properly 
from flask import Flask, render_template, request, url_for
import pickle

#Initializing the application
app = Flask(__name__)

#Loading in the logistic regression trained model using pickle.load function
with open("lg_model.pkl", "rb") as f :
    model = pickle.load(f)

#Loading in the countvectorizer using pickle.load function 
with open("countvectorizer.pkl", "rb") as f:
    vectorizer = pickle.load(f)

#Intializung the route and using the GET retrieveing the route when the user loads the webpage and POST to submit the results back 
#to the user when the email text has been sent. 
@app.route("/", methods=["GET", "POST"])
def index():

    #Intialized place holders and set them to default values 
    #These default values will be passed to the GET method when the webpage is loaded up.   
    email_text = ""
    label = None
    phishing_conf = None
    legitimate_conf = None

    if request.method == "POST":
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

    #Returning the required information 
    return render_template(
        "index.html",
        email_text=email_text,
        prediction=label,
        legitimate_confidence=legitimate_conf,
        phishing_confidence=phishing_conf

    )

#Running the application by using the app.run functionality in Flask 
if __name__ == "__main__":
    app.run(debug=True)

        





