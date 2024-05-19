'''
import socket
import os
import sys
#from client_commands import command_handler


def start_client(server_name, server_port):
    #the client's socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #attempt to connect to the server
    client_socket.connect((server_name, server_port))

    print("meow1fr")
    welcome_message = client_socket.recv(1024).decode()
    print(welcome_message)
    option_message = client_socket.recv(1024).decode()
    print(option_message)
    #stops here
    print("meow1")

    while(True):

        print("meow2")
        #get user input
        user_input = input("Secure-Chat> ")

        #if(user_input == "quit" or "exit"):
         #   print("Goodbye")
          #  sys.exit(1)

        #send user_input to the server
        client_socket.send(user_input.encode())

        server_response = client_socket.recv(1024).decode()
        print (server_response)

        #client_handler(server_response, client_socket)


if __name__ == "__main__":
    #check if both server_name and server_port are provided
    if len(sys.argv) != 3:
        print("Usage: python3 client.py <serverMachine> <serverPort>")
        print("Use 127.0.0.1 as <serverMachine> when running on same machine")
        sys.exit(1)

    #get server_namd and server_port from command-line args
    server_name = sys.argv[1]

    try:
        #convert the provided port to an int
        server_port = int(sys.argv[2])
    except ValueError:
        print("Invalid port number. Please provide a valid integer.")
        sys.exit(1)

    start_client(server_name, server_port)'''

import socket
import os
import sys
import rsa



def start_client(server_name, server_port):
    #the client's socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #attempt to connect to the server
    client_socket.connect((server_name, server_port))

    welcome_message = client_socket.recv(1024).decode()
    print(welcome_message)

    # Load server's public key (assuming it's retrieved from the server beforehand)
    with open('server_public.pem', 'rb') as f:
        server_public_key = rsa.PublicKey.load(f.read())

    while(True):

        #get user input
        user_input = input("Secure-Chat> ")

        # Encrypt message using server's public key
        encrypted_message = rsa.encrypt(user_input.encode(), server_public_key).decode()

        #send user_input to the server
        client_socket.send(encrypted_message.encode())

        server_response = client_socket.recv(1024).decode()
        print (server_response)

    client_socket.close()


        #client_handler(server_response, client_socket)



if __name__ == "__main__":
    #check if both server_name and server_port are provided
    if len(sys.argv) != 3:
        print("Usage: python3 client.py <serverMachine> <serverPort>")
        print("Use 127.0.0.1 as <serverMachine> when running on same machine")
        sys.exit(1)

    #get server_namd and server_port from command-line args
    server_name = sys.argv[1]

    try:
        #convert the provided port to an int
        server_port = int(sys.argv[2])
    except ValueError:
        print("Invalid port number. Please provide a valid integer.")
        sys.exit(1)

    start_client(server_name, server_port)