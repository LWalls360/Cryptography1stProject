from flask import request
from flask_socketio import emit
from .cryptoUtils import CryptoUtils

from .extensions import socketio

users = {}

@socketio.on("connect")
def handle_connect():
    if len(users) == 2:
        print(f"Client rejected")
        return False
    print(f"Client connected! {len(users)} Users connected: {users}")

@socketio.on("disconnect")
def handle_disconnect():
    users.pop(request.sid)

@socketio.on("user_log_in")
def handle_user_join(username):
    print(f"User {username} joined!")
    users[request.sid] = username
    emit("user_log_in_message", {"message": f"User {username} logged into chat", "username": username}, broadcast=True)

@socketio.on("new_message")
def handle_new_message(message):
    print(f"New message: {message}")
    username = users[request.sid]
    emit("chat", {"message": message, "username": username}, broadcast=True)