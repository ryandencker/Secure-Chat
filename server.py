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
from Cryptodome.Util.Padding import unpad
from Cryptodome.Cipher import AES
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256

online_users = {}
clients = []  # List to keep track of connected clients
with open('online.txt', 'w') as f:
    f.truncate()
#generate server symm key
symm_key = get_random_bytes(16)
# print(symm_key, "\n")

def broadcast(message, current_client):
    # padded_msg = pad(message, 16)
    # # print(padded_msg)
    # AES_enc_cipher = AES.new(symm_key, AES.MODE_ECB)   
    # AES_msg = AES_enc_cipher.encrypt(padded_msg)
    #implemet dig sig for rsa or dsa
    for client in clients:
        if client != current_client:
            try:
                # client.send(message)
                client.send(AES_msg)
            except Exception as e:
                print(f"Error sending message to a client: {e}")
                client.close()
                clients.remove(client)

def handle_client(client_socket, addr):
    try:
        
        #append socket associated w/client pub key to same line as assocaited rand num
        with open("pubkey_file_number.txt", "a") as f:
            f.write(f"sock:{client_socket}\n")
        # print('actually here')
        
        
        with open("pubkey_file_number.txt", "r") as f:
           for line in f:
               filenumber, sock = line.strip().split(" sock:")
            #    print(filenumber, sock)
               if sock == str(client_socket):
                    pub_file = filenumber + "public_key.pem"
                    pubkey = RSA.import_key(open(pub_file).read())
                   
                    # print("in hereee")
                    cipher_rsa = PKCS1_OAEP.new(pubkey)
                    enc_symm_key = cipher_rsa.encrypt(symm_key)
                    # print("enc key:", enc_symm_key)
                    key_length = len(enc_symm_key).to_bytes(5, byteorder='big')
                    # enc_key_header = key_length + enc_symm_key
                    # print(key_length, "key legnth \n")
                    client_socket.send(key_length)
                    client_socket.send(enc_symm_key)
                    accout_option(client_socket)
                    break
        # print('here')
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
        enc_msg = gen_AES_enc(options_msg.encode())
        connection_socket.send(enc_msg)

        client_command = connection_socket.recv(1024)
        AES_dec_command = gen_AES_dec(client_command)

        # print(AES_dec_command)

        if AES_dec_command == b'1':
            create_account(connection_socket)
        elif AES_dec_command == b'2':
            login(connection_socket)#,public_key)
            break
        elif AES_dec_command == b'3':
            ##fix
            disconnect_msg = "Disconnecting...\n"
            enc_dis_msg = gen_AES_enc(disconnect_msg.encode())
            connection_socket.send(enc_dis_msg)
            connection_socket.close()
            return
        else:
            invalid = "Invalid choice. Please try again\n"
            AES_enc_invalid = gen_AES_enc(invalid.encode())
            connection_socket.send(AES_enc_invalid)

def command_handler(connection_socket):
    clients.append(connection_socket)
    while True:
        welcome = "\nWelcome User!\n\nWhat would you like to do? \n\nPress 1 to see who is online\nPress 2 to send a message\nPress 3 to disconnect"
        
        enc_welcome= gen_AES_enc(welcome.encode())
        connection_socket.send(enc_welcome)
        client_command = connection_socket.recv(1024)
        AES_dec_command = gen_AES_dec(client_command)#.decode()

        print("Received command:",AES_dec_command)

        if AES_dec_command == b'1':
            show_online(connection_socket)
        elif AES_dec_command == b'2':
            print("Client selected to send a message.")
            rsa_or_dsa = "Send by RSA or DSA? (Enter 'rsa' or 'dsa'): "
            rsa_or_dsa_enc = gen_AES_enc(rsa_or_dsa.encode())
            connection_socket.send(rsa_or_dsa_enc)
            encryption_type = connection_socket.recv(1024)
            enc_type_dec = gen_AES_dec(encryption_type).lower()
            print(f"Client selected encryption type: {enc_type_dec}")

            if enc_type_dec not in ['rsa', 'dsa']:
                invalid_msg = "Invalid encryption type. Please enter 'rsa' or 'dsa'.\n"
                enc_msg =  gen_AES_enc(invalid_msg)
                connection_socket.send(enc_msg)
                continue
            msg = "Enter your message: "
            aes_msg = gen_AES_enc(msg.encode())
            connection_socket.send(aes_msg)
            message = connection_socket.recv(1024)
            # dec_message = gen_AES_dec(message)
            print(f"Client entered message: {message}")

            if encryption_type == 'rsa':
                print("Calling send_message_rsa")
                send_message_rsa(message, connection_socket)
            elif encryption_type == 'dsa':
                print("Calling send_message_dsa")
                send_message_dsa(message, connection_socket)
            send_msg = "Enter your message"
            enc_send_msg = gen_AES_enc(send_msg.encode())
            connection_socket.send(enc_send_msg)
            message = connection_socket.recv(1024)
            AES_dec_msg = gen_AES_dec(message)
            #message encrypted w/AES in broadcast function
            broadcast(AES_dec_msg, connection_socket)
           
        elif AES_dec_command == b'3':
            disconnect_msg = "Disconnecting...\n"
            enc_dis_msg = gen_AES_enc(disconnect_msg.encode())
            connection_socket.send(enc_dis_msg)
            remove_from_online(connection_socket)
            connection_socket.close()
            break

def create_account(connection_socket):
    username_msg = "Please enter your username: "
    user_enc_msg = gen_AES_enc(username_msg.encode())
    connection_socket.send(user_enc_msg)
    # print(user_enc_msg)
    username = connection_socket.recv(1024)
    AES_dec_user = gen_AES_dec(username).decode()
    # print(AES_dec_user)
    password_msg = "Please enter your password: "
    password_enc_msg = gen_AES_enc(password_msg.encode())
    connection_socket.send(password_enc_msg)
    password = connection_socket.recv(1024)
    AES_dec_pass = gen_AES_dec(password).decode()
    # print(AES_dec_pass)

    hashedPassword = bcrypt.hashpw(AES_dec_pass.encode('utf-8'), bcrypt.gensalt())
    user_id = generate_unique_user_id()

    with open("db.txt", "a") as f:
        f.write(f"{AES_dec_user} {hashedPassword.decode('utf-8')} {user_id}\n")

    created_msg = "Account has been created!\n"
    create_enc_msg = gen_AES_enc(created_msg.encode())

    connection_socket.send(create_enc_msg)

def login(connection_socket):#,public_key):
    while True:
        username_msg = "Please enter your username: "
        username_enc_msg = gen_AES_enc(username_msg.encode())
        connection_socket.send(username_enc_msg)
        username = connection_socket.recv(1024)
        AES_dec_user = gen_AES_dec(username).decode()
        # print(AES_dec_user)
        password_msg = "Please enter your password: "
        password_enc_msg = gen_AES_enc(password_msg.encode())
        connection_socket.send(password_enc_msg)
        password = connection_socket.recv(1024)
        AES_dec_pass = gen_AES_dec(password).decode()
        # print(AES_dec_pass)
        user_found = False
        with open("db.txt", "r") as f:
            for line in f:
                stored_username, stored_password, user_id = line.strip().split(" ")
                if AES_dec_user == stored_username and bcrypt.checkpw(AES_dec_pass.encode('utf-8'), stored_password.encode('utf-8')):
                    user_found = True
                    place_online(AES_dec_user)
                    return
        if not user_found:
            #add enc here for aes ad stuff
            msg = "Your username or password is wrong. Try again\n"
            enc_msg = gen_AES_enc(msg.encode())
            connection_socket.send(enc_msg)

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
    enc_file = gen_AES_enc(file_contents.encode())
    connection_socket.sendall(enc_file)

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

def gen_AES_enc(message):
    padded_msg = pad(message, 16)
    # print(padded_msg)
    AES_enc_cipher = AES.new(symm_key, AES.MODE_ECB)   
    AES_msg = AES_enc_cipher.encrypt(padded_msg)
    return AES_msg

def gen_AES_dec(message):
    AES_dec_cipher = AES.new(symm_key, AES.MODE_ECB)
    AES_dec_msg = AES_dec_cipher.decrypt(message)
    unpadded_msg = unpad(AES_dec_msg, 16)
    return unpadded_msg

def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(5)
    print(f"Server started on port {port}")

    while True:
        client_socket, addr = server_socket.accept()
        # print(client_socket, addr)

        print(f"Client connected from: {addr}")
        client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_thread.start()

def send_message_rsa(message, client_socket):
    try:
        keys = RSA.generate(2048)
        pub_key = keys.publickey().export_key()
        priv_key = keys.export_key()

        # Write the public key to the file
        with open("rsa_public_keys.txt", "a") as f:
            f.write(f"{client_socket.getpeername()}  {pub_key}\n")

        # Here you would typically encrypt the message with the public key
        # For demonstration, we're just sending the message prefixed with "RSA: "
        print(f"Sending message with RSA: {message}")
        enc_msg = gen_AES_enc(message.encode())
        client_socket.send(f"RSA: {message}".encode())
    except Exception as e:
        print(f"An error occurred while sending the message with RSA: {e}")

def send_message_dsa(message, client_socket):
    try:
        print("Inside send_message_dsa")

        # Generate DSA key pair
        key = DSA.generate(2048)
        pub_key = key.publickey().export_key(format='PEM')
        priv_key = key.export_key(format='PEM')

        # Print the DSA keys
        print(f"DSA Public Key:\n{pub_key.decode('utf-8')}")
        print(f"DSA Private Key:\n{priv_key.decode('utf-8')}")

        # Write the public key to a file for record-keeping
        with open("dsa_public_keys.txt", "a") as f:
            f.write(f"{client_socket.getpeername()}  {pub_key.decode('utf-8')}\n")
        print("Public key written to file.")

        # Sign the message
        h = SHA256.new(message)  # Create a SHA-256 hash of the message
        signer = DSS.new(key, 'fips-186-3')  # Create a signer object using the DSA key
        signature = signer.sign(h)  # Sign the hash with the DSA key

        # Print the signature
        print(f"Signature: {signature.hex()}")

        print("Message signed.")

        # Combine public key, signature, and message into one package
        dsa_message = b"DSA: " + message  # Prefix message with "DSA: "
        combined_message = pub_key + b"\n" + signature + b"\n" + dsa_message

        # Send the combined message to the client
        client_socket.sendall(combined_message)
        print("Message sent.")
        print(f"Sending message with DSA: {message.decode()}")

    except Exception as e:
        print(f"An error occurred while sending the message with DSA: {e}")

if __name__ == "__main__":
    port = 12345
    start_server(port)# import socket
