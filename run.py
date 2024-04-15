from Encrypted_chat_room import create_app, socketio

app = create_app()

socketio.run(app)