Secure Chat created by:

Ryan Dencker
Brody Whelan
Brandon Nguyen
Ricky Truckner
Edgardo Arteaga
Hart Zhang

Contributions
Ryan Dencker - set up initial server and client connectivity, set up the database and online files, and made users able to sign up and log in

Brody Whelan

Brandon Nguyen - set up the DSA function to generate a DSA key pair, sign the message using the private key, combine the public key, signature, and message, and then send it to the client. Added an option to choose between sending by DSA or RSA

Ricky Truckner - Enabled secure communication by implementing RSA for key exchange. This establishes a secure channel for distributing symmetric keys to both client and server, ensuring message encryption.

Edgardo Arteaga

Hart Zhang  - ensure server and client communication create a socket, build remove_from_online broadcast generate_unique_user_id start_server, improved command_handler and accout_handler to able send messages and esbtablish a strong connections allow mutiple users to join

Instructions
1. Run the server.py and specify the port number you want the server to run on
  ex. python3 server.py
2. Run the client.py (127.0.0.1 if running locally)
  ex. python3 client.py
3. After running the server and client, you should be connected to the server and prompted to log in, sign in, or quit press 1 ,2 ,3 
4. Once creating an account, you have the option to see everyone online and connect to anyone online press 1 , 2 ,3
5. When connected to another person, you can send messages and the server will encrypt all the messages over the network press 2 
