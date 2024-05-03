import socket
import os
import sys



def start_client(server_name, server_port):
    #the client's socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #attempt to connect to the server
    client_socket.connect((server_name, server_port))

    welcome_message = client_socket.recv(1024).decode()
    print(welcome_message)

    while(True):

        #get user input
        user_input = input("Secure-Chat> ")

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

    start_client(server_name, server_port)