from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from pymongo import MongoClient 
import bcrypt 
import numpy as np # type: ignore
import requests

from keras.applications import InceptionV3 # type: ignore
from keras.applications.inception_v3 import preprocess_input # type: ignore
from keras.applications import imagenet_utils # type: ignore
from tensorflow.keras.preprocessing.image import img_to_array # type: ignore
from PIL import Image
from io import BytesIO

app = Flask(__name__)
api = Api(app)

# Load the pre trained model
pretrained_model = InceptionV3(weights="imagenet")


# Initialize Mongoclien
client = MongoClient("mongodb://db:27017")

# create a new db and collection
db = client.ImageRecognition
users = db["Users"]

def user_exists(username):
    if users.count_documents({"Username":username}) == 0:
        return False
    else:
        return True
    
class Register(Resource):
    def post(self):
        # We first get the posted data
        posted_data = request.get_json()

        # Get username and password
        username = posted_data["username"]
        password = posted_data["password"]

        # Check if user already exist
        if user_exists(username):
            return jsonify({
                "status": 301,
                "msg": "Invalid username, user already exists"
            })
        # If user is new, hash password
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Store the new user in database
        users.insert_one({
            "Username": username,
            "Password": hashed_pw,
            "Tokens": 4
        })

        # Return success
        return jsonify({
                "status": 200,
                "msg": "You have successfull signed up"
            })

def verify_pw(username, password):
    if not user_exists(username):
        return  False
    
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

def verify_credentials(username, password):
    if not user_exists(username):
        return generate_return_dictionary(301, "Invalid Username"), True
    
    correct_pw = verify_pw(username, password)

    if not correct_pw:
        return generate_return_dictionary(302, "Incorrect Password"), True
    
    return None, False

def generate_return_dictionary(status, msg):
    ret_json = {
        "status": status,
        "msg": msg
    }
    return ret_json

class Classify(Resource):
    def post(self):
        # Get posted data
        posted_data = request.get_json()

        # Get credentials and url
        username = posted_data["username"]
        password = posted_data["password"]
        url = posted_data["url"]

        # Verify credentials
        ret_json, error = verify_credentials(username, password)
        if error:
            return jsonify(ret_json)

        # Check for tokens
        tokens = users.find({
            "Username": username
        })[0]["Tokens"]

        if tokens <= 0:
            return jsonify(generate_return_dictionary(303,"Not Enough Tokens"))

        # Classify the image
        if not url:
            return jsonify(({"error":"No url provided"}), 400)
        
        # Load image from URL
        response = requests.get(url)
        img = Image.open(BytesIO(response.content))

        # Pre process the image
        img = img.resize((299,299))
        img_array = img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_array)

        # Make prediction
        prediction = pretrained_model.predict(img_array)
        actual_prediction = imagenet_utils.decode_predictions(prediction, top=5)

        # Return classification
        ret_json = {}
        for pred in actual_prediction[0]:
            ret_json[pred[1]] = float(pred[2]*100)

        # ImageNet class id, class name, confidence in prediction
        # ('798746', "Class name", confidence)

        # reduce token
        users.update_one({
            "Username": username
        },{
            "$set":{
                "Tokens": tokens - 1
            }
        })
        return jsonify(ret_json)
    
class Refill(Resource):
    def post(self):
        # Get posted data
        posted_data = request.get_json()

        # get credentials
        username = posted_data["username"]
        password = posted_data["admin_pw"]
        amount = posted_data["amount"]

        # check if user exists
        if not user_exists(username):
            return jsonify(generate_return_dictionary(301, "Invalid Username"))
        
        # check admin password
        correct_pw = "abc123"
        if not password == correct_pw:
            return jsonify(generate_return_dictionary(302, "Incorrect password"))        

        # update tokens
        users.update_one({
            "Username":username
        },{
            "$set":{
                "Tokens":amount
            }
        })
        return jsonify(generate_return_dictionary(20, "Refilled")) 



api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')

if __name__ == '__main__':
    app.run(host='0.0.0.0')


        