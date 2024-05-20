import socket
import threading
import random
import sys
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Util.Padding import unpad
from Cryptodome.Util.Padding import pad
from Cryptodome.Cipher import AES

class Client:
    def __init__(self):
        #symm key is accessible to all functions in client class
        self.symm_key = None
    def receive_messages(self,client_socket,priv_file_name):
        # receive symmetric key
        
        while True:
            try:
                # receive encrypted symmetric key
                key_length_msg = client_socket.recv(5)
                key_length = int.from_bytes(key_length_msg, byteorder='big')
                # message = client_socket.recv(4096)
                #print(key_length)
                encrypted_key = b''
                bytes_received = 0
                data = None
                #data varaible is to store and make sure all bytes of key are received
                while bytes_received < key_length:
                    data = client_socket.recv(key_length - bytes_received)
                    if not data:
                        raise Exception("Connection closed unexpectedly while receiving encrypted key")
                    encrypted_key += data
                    bytes_received += len(data)
                
               # print(data, '\n')
                if data:
                    private_key = RSA.import_key(open(priv_file_name).read())

                    dec_cipher_rsa = PKCS1_OAEP.new(private_key)
                    self.symm_key = dec_cipher_rsa.decrypt(data)
                   
                    break
            except Exception as e:
                 print(f"An error w/the symmetric key, press 3 to quit and try again: {e}")
                 client_socket.close()
                 sys.exit(1)
                 break
        # wait for messages/chat
        while True:
            try:
                message = client_socket.recv(1024)#.decode()
               
                if message:
                    #decrypt/verify digsig then decrypt with aes_dec_cipher
                    AES_dec_cipher = AES.new(self.symm_key, AES.MODE_ECB)
                    AES_dec_msg = AES_dec_cipher.decrypt(message)
                    unpadded_msg = unpad(AES_dec_msg, 16)
                    #dsa or rsa decryption or whatever here
                    #dsa_rsa_dec =
                    #decrypt output from dsa/rsa w/symm key and output the message
                    # 
                    # print("\n" + message)  # Print the incoming message
                    # print("Secure-Chat> ", end='', flush=True)  # Reprint the prompt
                    print("\n" + unpadded_msg.decode())  # Print the incoming message
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
                
                AES_enc_input = self.gen_AES_enc(user_input.encode())
                
                if user_input:
                    client_socket.send(AES_enc_input)
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

    def gen_AES_enc(self, message):
        padded_msg = pad(message, 16)
        AES_enc_cipher = AES.new(self.symm_key, AES.MODE_ECB)   
        AES_msg = AES_enc_cipher.encrypt(padded_msg)
        return AES_msg
if __name__ == "__main__":
    client = Client()
    server_name = "127.0.0.1"
    server_port = 12345
    client.start_client(server_name, server_port)
