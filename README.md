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
Brandon Nguyen
Ricky Truckner
Edgardo Arteaga
Hart Zhang  - ensure server and client communication create a socket, build remove_from_online broadcast generate_unique_user_id start_server, improved command_handler and accout_handler to able send messages and esbtablish a strong connections allow mutiple users to join

Instructions
1. Run the server.py and specify the port number you want the server to run on
  ex. python3 server.py 4444
2. Run the client.py and specify the IP address and the port of the server that is running (127.0.0.1 if running locally)
  ex. python3 client.py 127.0.0.1 4444
3. After running the server and client, you should be connected to the server and prompted to log in, sign in, or quit
4. Once creating an account, you have the option to see everyone online and connect to anyone online
5. When connected to another person, you can send messages and the server will encrypt all the messages over the network
