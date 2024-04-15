function main() {
    const fileInput = document.querySelector("#keyfile-container input[type=file]");
    const socket = io({autoConnect: false});
    let username = "";
    let filestr = "";

    document.getElementById("generate-keys").addEventListener("click", function() {            
        document.getElementById("page-title").style.display = "none";
        document.getElementById("landing").style.display = "none";
        document.getElementById("create-user-input-boxes").style.display = "block";
    })

    document.getElementById("log-in-user").addEventListener("click", function() {            
        document.getElementById("landing").style.display = "none";
        document.getElementById("page-title").style.display = "none";
        document.getElementById("login-user-input-boxes").style.display = "block";
    })

    document.getElementById("create-user").addEventListener("click", function() {
        username = document.getElementById("new-user-username").value;
        let password = document.getElementById("new-user-password").value;

        let data = {
            "username": username,
            "password": password,
        }
        fetch(create_user_url, {
            "method": "POST",
            "headers": { "Content-Type": "application/json" },
            "body": JSON.stringify(data),
        }).then( res => {return res.blob();
        }).then(blob => { download(blob, "EncryptedUserKeys.keyfile")
        }).then(alert("User created and keys generated successfully!"))
        .catch(err=>console.log(err));
        
        document.getElementById("create-user-input-boxes").style.display = "none";            
        document.getElementById("landing").style.display = "block";
        document.getElementById("page-title").style.display = "block";
        username = "";
    })

    document.getElementById("log-in-user-to-chat").addEventListener("click", function() {
        username = document.getElementById("login-username").value;
        let password = document.getElementById("login-password").value;
        let reader = new FileReader();
        reader.addEventListener("load", function (e) {
            // Things to do after read as text finished
            filestr = e.target.result;

            let data = {
                "username": username,
                "password": password,
                "keyfile": filestr,
            }
            fetch(log_in_user_url, {
                "method": "POST",
                "headers": { "Content-Type": "application/json" },
                "body": JSON.stringify(data),
            });
    
            socket.connect();
    
            socket.on("connect_error", function(){
                alert("2 users are already connected!")
            });
            
            socket.on("connect", function() {
                socket.emit("user_log_in", username);
            });
            
            document.getElementById("login-user-input-boxes").style.display = "none";            
            document.getElementById("page-title").style.display = "none";            
            document.getElementById("chat").style.display = "block";
        });

        reader.readAsText(fileInput.files[0]);
    })

    fileInput.onchange = () => {
        if (fileInput.files.length > 0) {
            const fileName = document.querySelector("#keyfile-container .file-name");
            fileName.textContent = fileInput.files[0].name;
        }
    };

    document.getElementById("message").addEventListener("keyup", function (event) {
        if (event.key == "Enter") {
            let message = document.getElementById("message").value;
            socket.emit("new_message", message);
            document.getElementById("message").value = "";
        }
    })
    document.getElementById("send-message").addEventListener("click", function (event) {
        let message = document.getElementById("message").value;
        socket.emit("new_message", message);
        document.getElementById("message").value = "";
    })

    socket.on("chat", function(data) {
        let ul = document.getElementById("chat-messages");
        let li = document.createElement("li");
        li.appendChild(document.createTextNode(data["username"] + ": " + data["message"]));
        if (data["username"] === username ) {
            li.classList.add("has-text-info");
            li.style.textAlign = "left";
        } else {
            li.classList.add("has-text-primary");   
            li.style.textAlign = "right";       
        }
        ul.appendChild(li);
        li.scrollIntoView({behavior: "smooth"});
    })

    socket.on("user_log_in_message", function(data) {
        let ul = document.getElementById("chat-messages");
        let li = document.createElement("li");
        li.appendChild(document.createTextNode(data["message"]));
        ul.appendChild(li);
        li.scrollIntoView({behavior: "smooth"});
    })
}

main();