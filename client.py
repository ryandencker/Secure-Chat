import socket
import threading
import random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Util.Padding import unpad

class Client:
    def __init__(self):
        #symm key is accessible to all functions in client class
        self.dec_symm_key = None
    def receive_messages(self,client_socket,priv_file_name):
        # receive symmetric key
        
        while True:
            try:
                # receive encrypted symmetric key
                # occasional ciphertext length error, not sure how to fix
                message = client_socket.recv(4096)
                # print(message, '\n')
                if message:
                    private_key = RSA.import_key(open(priv_file_name).read())

                    dec_cipher_rsa = PKCS1_OAEP.new(private_key)
                    # print("Dec cipher rsa:", dec_cipher_rsa, '\n')
                    self.dec_symm_key = dec_cipher_rsa.decrypt(message)
                    # write to file so client can access it whenever they need
                    f = open("symm_key.txt", "a")
                    # print("Decrypted message:", dec_symm_key, '\n')
                    # print(f"Decrypted symmetric key: {self.dec_symm_key}")
                    break
            except Exception as e:
                 print(f"An error occurred while receiving the symmetric key: {e}")
                 break
        # wait for messages/chat
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

    def send_messages(self, client_socket):
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

    def start_client(self,server_name, server_port):
        keys = RSA.generate(2048)
        pub_key = keys.publickey()
        pem_pub_key = pub_key.export_key()
        private_key = keys.export_key()
        
        #generate unique number for file name
        unique_number = random.randint(1000, 9999)
        while True:
            with open("pubkey_file_number.txt", "r") as f:
                for line in f:
                    if unique_number == line:
                        unique_number = random.randint(1000, 9999)
                        break
                break
        str_unique_number = str(unique_number)
        
        #write the file number to file
        with open("pubkey_file_number.txt", "a") as f:
            f.write(f"{str_unique_number} ")
        
        #create file name for client pub key and write to it
        file_name = str_unique_number + "public_key.pem"
        with open(file_name, "wb") as file:
            file.write(pem_pub_key)
        
        #create file name for client priv key and write to it
        priv_file_name = str(unique_number) + "private_key.pem"
        with open(priv_file_name, "wb") as file:
            file.write(private_key)

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_name, server_port))

        # Start a thread to listen for messages from the server
        receive_thread = threading.Thread(target=self.receive_messages, args=(client_socket,priv_file_name,))#str_unique_number))
        receive_thread.start()
    
        # Handle sending messages in the main thread
        self.send_messages(client_socket)

if __name__ == "__main__":
    client = Client()
    server_name = "127.0.0.1"
    server_port = 12345
    client.start_client(server_name, server_port)
