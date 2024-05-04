import os
import bcrypt
import pwinput
import random
import sys

def accout_option(client_command, connection_socket):

    while (True):

        print(client_command)

        if client_command == b'1':
            create_account(connection_socket)
        elif client_command == b'2':
            login()
        elif client_command == b'3':
            disconnect_msg = "Disconnecting from server..."
            connection_socket.send(disconnect_msg.encode())
            connection_socket.close()
            break
        else:
            invalid = "Invalid choice. Please try again\n"
            connection_socket.send(invalid.encode())
            
        break
            

'''
def command_handler(client_command, connection_socket):
    # Get the "arguments from the client and split them up"
    temp_list = client_command.split()
    command_arguments = []
    
    for i in temp_list:
        command_arguments.append(i.decode())
    
    command = command_arguments[0]

    # See what command the user inputted
    if command == "get":
        return handle_get_command(command_arguments)
    elif command == "put":
        return handle_put_command(command_arguments, connection_socket)
    elif command == "ls":
        return handle_ls_command()
    elif command == "quit":
        return "quit"
    else:
        return "Invalid command. Please enter a valid command."
        '''
    
def create_account(connection_socket):

    #get username and password
    username_msg = "Please enter your username: "
    connection_socket.send(username_msg.encode())
    username = connection_socket.recv(1024).decode()
    print(username)
    password_msg = "Please enter your password: "
    connection_socket.send(password_msg.encode())
    password = connection_socket.recv(1024).decode()
    print(password)
    
    #encrypt password
    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    print(hashedPassword)

    #create 5 digit user ID
    user_id = random.randint(10000, 99999)
    print(user_id)

    #write credentials to db.txt
    f = open("db.txt", "a")
    f.write(f"{username} {hashedPassword.decode('utf-8')} {user_id}\n")
    f.close



    #idk how to add this, this blocks out the users input when typing password
    #password = pwinput.pwinput(prompt="Please enter your password: ")
    
    #open and write username password and user id to db.txt

    #print message
    print("\nAccount has been created!")
    print("Your User ID is: ", user_id)

    #send message to client
    created_msg = "Account has been created!\n"
    connection_socket.send(created_msg.encode())

def login():
    print("still working on this")