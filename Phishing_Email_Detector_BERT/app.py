#Importing the required libraries needed for the Flask backend to function properly 
from flask import Flask, render_template, request, url_for
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

#Initializing the application
app = Flask(__name__)

#Loading the tokenizer and trained BERT model into the Flask Application Backend 
model = AutoModelForSequenceClassification.from_pretrained("bert_phishing_model")
tokenizer = AutoTokenizer.from_pretrained("bert_phishing_model")

model.eval()

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

        #Tokenizing the email text when upon entered by the user 
        inputs = tokenizer(
            email_text,
            padding=True,
            truncation=True,
            max_length=256,
            return_tensors="pt"
        )

        # Handles making the predictions 
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1).squeeze().tolist()

        # Determine the prediction is either Phishing or Legitimate from the predicted class 
        predicted_class = torch.argmax(logits, dim=1).item()
        label = "Phishing" if predicted_class == 1 else "Legitimate"

        #Handles calculating the probabilties for either phishing or legitimate 
        legitimate_conf = round(probabilities[0] * 100, 2)
        phishing_conf = round(probabilities[1] * 100, 2)

    #Returning the required information to the HTML template to be displayed on the webpage 
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