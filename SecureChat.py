import bcrypt
import pwinput
import random


def place_online(username):
    f = open("online.txt", "a")
    f.write(f"{username} ")

def create():
    #get username and password
    username = input("Please enter your username: ")
    password = pwinput.pwinput(prompt="Please enter your password: ")

    #hash password
    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    #generate random 5 digit user ID
    user_id = random.randint(10000, 99999)
    

    f = open("db.txt", "a")
    f.write(f"{username} {hashedPassword.decode('utf-8')} {user_id}\n")
    f.close
    print("\nAccount has been created!")
    print("Your User ID is: ", user_id)



def login():
    username = input("Please enter your username: ")
    password = pwinput.pwinput(prompt="Please enter your password: ")
    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    f = open("db.txt", "r")
    for line in f:
        stored_username, stored_password, user_id = line.strip().split(" ")
        if username == stored_username:
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                f.close()
                print("Welcome ", username)
                place_online(username)
                exit()
    f.close()
    print("Your username or password is wrong. Try again")
    return

def main():
    print("\n-------WELCOME TO SECURE CHAT-------\n\n")

    while(True):
        user_input = input("Press 1 to create an account, 2 to log into an existing account, or 3 to quit: ")

        if user_input == '1':
            create()
        elif user_input == '2':
            login()
        elif user_input == '3':
            break
        else:
            print("Invalid choice. Please try again")

if __name__ == "__main__":
    main()