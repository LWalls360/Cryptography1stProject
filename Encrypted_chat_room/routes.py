from flask import Blueprint, render_template
from flask import request

main = Blueprint("main", __name__)

@main.route("/")
def index():
    return render_template("index.html")

@main.post("/create_user")
def create_user():    
    print(f"New user: {request.json}")
    # Do something and generate keys
    return {"status": "success"}

@main.post("/log_in_user")
def log_in_user():    
    print(f"New logged in user: {request.json}")
    # Do something
    return {"status": "success"}
