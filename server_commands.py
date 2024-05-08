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
            login(connection_socket)
            break
        elif client_command == b'3':
            #this needs to be worked on
            print("disconnect client")
        else:
            invalid = "Invalid choice. Please try again\n"
            connection_socket.send(invalid.encode())
            
        options_msg = "Press 1 to create an account, 2 to log into an existing account, or 3 to quit:\n "
        connection_socket.send(options_msg.encode())

        #get user command
        client_command = connection_socket.recv(1024)
            


def command_handler(connection_socket):
    # Get the "arguments from the client and split them up"

    while (True):
        connection_socket.send(("\nWelcome User!\n\nWhat would you like to do? \n\nPress 1 to see who is online\nPress 2 to connect to someone online\nPress 3 to disconnect").encode())
        client_command = connection_socket.recv(1024)
        print("here is what is being passes to command handler")
        print(client_command)
        print(connection_socket)

        if client_command == b'1':
            show_online(connection_socket)
        elif client_command == b'2':
            connect_client(connection_socket)
        elif client_command == b'3':
            #this needs to be worked on
            print("disconnect client")
    
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

def login(connection_socket):

    while (True):
        #get username and password
        username_msg = "Please enter your username: "
        connection_socket.send(username_msg.encode())
        username = connection_socket.recv(1024).decode()
        print(username)
        password_msg = "Please enter your password: "
        connection_socket.send(password_msg.encode())
        password = connection_socket.recv(1024).decode()
        print(password)

        user_found = False
        f = open("db.txt", "r")
        for line in f:
            stored_username, stored_password, user_id = line.strip().split(" ")
            if username == stored_username:
                if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                    f.close()
                    user_found = True
                    #connection_socket.send(("Welcome " + username + "!").encode())
                    place_online(username)
                    return
        f.close()
        if(not user_found):
            connection_socket.send(("Your username or password is wrong. Try again\n").encode())

        print("meow")
        #connection_socket.send(("meow").encode())
        

def place_online(username):
# Open the file

    f = open("db.txt", "r")
    for line in f:
        stored_username, stored_password, user_id = line.strip().split(" ")
        if username == stored_username:
            l = open("online.txt", "a")
            l.write(f"{username} {user_id}\n")
            print("user added to online")
            break

def show_online(connection_socket):
    #shows the client who is online (online.txt)
    f = open("online.txt", "r")
    file_contents = f.read()
    connection_socket.sendall(file_contents.encode())
    
def connect_client(connection_socket):
    #still needs to be done, connects client to another client
    connection_socket.send(("Please enter the user ID of the person you would like to connect to").encode())
    user_id = connection_socket.recv(1024).decode()
    print("user would like to connect to ", user_id)
    connection_socket.send(("wow you are so awesome!!\nThis still needs to be worked on\n\n").encode())