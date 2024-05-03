import bcrypt
import pwinput


def create():
    username = input("Please enter your username: ")
    password = pwinput.pwinput(prompt="Please enter your password: ")
    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    f = open("db.txt", "a")
    f.write(f"{username} {hashedPassword.decode('utf-8')}\n")
    f.close
    print("Account has been created!")



def login():
    username = input("Please enter your username: ")
    password = pwinput.pwinput(prompt="Please enter your password: ")
    hashedPassword = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    f = open("db.txt", "r")
    for line in f:
        stored_username, stored_password = line.strip().split(" ")
        if username == stored_username:
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                f.close()
                print("Welcome ", username)
                exit()
    f.close()
    print("Your username or password is wrong. Try again")
    return

def main():
    print("\n-------WELCOME TO SECURE CHAT-------\n\n")
    user_input = input("Press 1 to create an account or press 2 to log into an existing account: ")

    if user_input == '1':
        create()
    elif user_input == '2':
        login()
    else:
        print("Invalid choice. Please try again")

if __name__ == "__main__":
    main()