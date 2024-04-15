import io
from flask import Blueprint, render_template, send_file
from flask import request
from .cryptoUtils import CryptoUtils

main = Blueprint("main", __name__)

@main.route("/")
def index():
    return render_template("index.html")

@main.post("/create_user")
def create_user():    
    print(f"New user: {request.json['username']}")
    privateAsymKey, publicAsymKey = CryptoUtils.generate_asymmetric_keys()
    privateSymKey = CryptoUtils.derive_symmetric_key(request.json['password'])
    keyFile = CryptoUtils.encrypt_keys_for_storage(request.json['username'],request.json['password'],privateAsymKey, publicAsymKey, privateSymKey)
    return send_file(keyFile, mimetype='text/plain', as_attachment=True, download_name="EncryptedUserKeys.keyfile")

@main.post("/log_in_user")
def log_in_user():    
    print(f"New logged in user: {request.json}")
    # Do something
    return {"status": "success"}
