import socket
import threading
import bcrypt
import random
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import DSA
from Cryptodome.PublicKey import RSA
# from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Util.Padding import pad

online_users = {}
clients = []  # List to keep track of connected clients

#generate server symm key
symm_key = get_random_bytes(16)
print(symm_key, "\n")

def broadcast(message, current_client):
    for client in clients:
        if client != current_client:
            try:
                client.send(message)
            except Exception as e:
                print(f"Error sending message to a client: {e}")
                client.close()
                clients.remove(client)

def handle_client(client_socket, addr):
    try:
        
        #append socket associated w/client pub key to same line as assocaited rand num
        with open("pubkey_file_number.txt", "a") as f:
            f.write(f"sock:{client_socket}\n")
        print('actually here')
        
        #encrypt server symm key w/client pub key
        with open("pubkey_file_number.txt", "r") as f:
           for line in f:
               filenumber, sock = line.strip().split(" sock:")
               print(filenumber, sock)
               if sock == str(client_socket):
                    pub_file = filenumber + "public_key.pem"
                    pubkey = RSA.import_key(open(pub_file).read())
                        
                   # encrypt symm key with the public key
                    print("in hereee")
                    cipher_rsa = PKCS1_OAEP.new(pubkey)
                    enc_symm_key = cipher_rsa.encrypt(symm_key)
                    print("enc key:", enc_symm_key)
                    client_socket.send(enc_symm_key)
                    accout_option(client_socket)
                    break
        print('here')
        command_handler(client_socket)
    except Exception as e:
        print(f"An error occurred with {addr}: {e}")
    finally:
        remove_from_online(client_socket)
        if client_socket in clients:
            clients.remove(client_socket)
        client_socket.close()

def accout_option(connection_socket):#,public_key):
    while True:
        options_msg = "Press 1 to create an account, 2 to log into an existing account, or 3 to quit:\n"
        connection_socket.send(options_msg.encode())

        client_command = connection_socket.recv(1024)
        print(client_command)

        if client_command == b'1':
            create_account(connection_socket)
        elif client_command == b'2':
            login(connection_socket)#,public_key)
            break
        elif client_command == b'3':
            connection_socket.send("Disconnecting...\n".encode())
            connection_socket.close()
            return
        else:
            invalid = "Invalid choice. Please try again\n"
            connection_socket.send(invalid.encode())

def command_handler(connection_socket):
    clients.append(connection_socket)
    while True:
        connection_socket.send(("\nWelcome User!\n\nWhat would you like to do? \n\nPress 1 to see who is online\nPress 2 to send a message\nPress 3 to disconnect").encode())
        client_command = connection_socket.recv(1024)
        print("Received command:", client_command)

        if client_command == b'1':
            show_online(connection_socket)
        elif client_command == b'2':
            connection_socket.send("Enter your message: ".encode())
            message = connection_socket.recv(1024)
            broadcast(message, connection_socket)
        elif client_command == b'3':
            connection_socket.send("Disconnecting...\n".encode())
            remove_from_online(connection_socket)
            connection_socket.close()
            break

def create_account(connection_socket):
    username_msg = "Please enter your username: "
    connection_socket.send(username_msg.encode())
    username = connection_socket.recv(1024).decode()
    password_msg = "Please enter your password: "
    connection_socket.send(password_msg.encode())
    password = connection_socket.recv(1024).decode()

    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user_id = generate_unique_user_id()

    with open("db.txt", "a") as f:
        f.write(f"{username} {hashedPassword.decode('utf-8')} {user_id}\n")

    created_msg = "Account has been created!\n"
    connection_socket.send(created_msg.encode())

def login(connection_socket):#,public_key):
    while True:
        username_msg = "Please enter your username: "
        connection_socket.send(username_msg.encode())
        username = connection_socket.recv(1024).decode()
        password_msg = "Please enter your password: "
        connection_socket.send(password_msg.encode())
        password = connection_socket.recv(1024).decode()

        user_found = False
        with open("db.txt", "r") as f:
            for line in f:
                stored_username, stored_password, user_id = line.strip().split(" ")
                if username == stored_username and bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                    user_found = True
                    place_online(username)
                    return
        if not user_found:
            connection_socket.send("Your username or password is wrong. Try again\n".encode())

def generate_unique_user_id():
    user_id = random.randint(10000, 99999)
    with open("db.txt", "r") as f:
        existing_ids = [line.strip().split(" ")[2] for line in f]
    while str(user_id) in existing_ids:
        user_id = random.randint(10000, 99999)
    return user_id

def place_online(username):
    with open("db.txt", "r") as f:
        for line in f:
            stored_username, stored_password, user_id = line.strip().split(" ")
            if username == stored_username:
                with open("online.txt", "a") as l:
                    l.write(f"{username} {user_id}\n")
                online_users[username] = user_id
                print("User added to online")
                break

def show_online(connection_socket):
    with open("online.txt", "r") as f:
        file_contents = f.read()
    connection_socket.sendall(file_contents.encode())

def remove_from_online(connection_socket):
    username = online_users.pop(connection_socket, None)
    if username:
        with open("online.txt", "r") as f:
            lines = f.readlines()
        with open("online.txt", "w") as f:
            for line in lines:
                if not line.startswith(username):
                    f.write(line)
        print(f"{username} has been removed from online list.")

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Server started on port {port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(client_socket, addr)

        print(f"Client connected from: {addr}")
        client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_thread.start()

if __name__ == "__main__":
    port = 12345
    start_server(port)# import socket
