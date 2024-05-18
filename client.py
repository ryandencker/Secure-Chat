import socket
import threading

def receive_messages(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode()
            if message:
                print("\n" + message)  # Print the incoming message
                print("Secure-Chat> ", end='', flush=True)  # Reprint the prompt
            else:
                break
        except Exception as e:
            print(f"An error occurred while receiving messages: {e}")
            break

def send_messages(client_socket):
    while True:
        try:
            user_input = input("Secure-Chat> ")
            if user_input:
                client_socket.send(user_input.encode())
                if user_input == "3":  # Disconnect command
                    break
        except Exception as e:
            print(f"An error occurred while sending messages: {e}")
            break

    client_socket.close()

def start_client(server_name, server_port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_name, server_port))

    # Start a thread to listen for messages from the server
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    # Handle sending messages in the main thread
    send_messages(client_socket)

if __name__ == "__main__":
    server_name = "127.0.0.1"
    server_port = 12345
    start_client(server_name, server_port)
