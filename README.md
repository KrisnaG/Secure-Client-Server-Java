# Secure Java Client-Server Application

This is a Secure Java client-server application for sending messages over a network. It consists of a server program and a client program that communicate with each other using sockets and specific commands.
It communicates using SSL/TLS protocol with the SSLServerSocket and SSLSocket and ensures secure data transmission by employing various security measures, including truststore management with keytool, 
symmetric encryption, and HMAC (Hash-based Message Authentication Code).

This application employs symmetric encryption and HMAC. Symmetric encryption ensures that the data transmitted between the server and client remains confidential by encrypting it using a shared key. 
HMAC guarantees the integrity of the data by appending a hash-based message authentication code to each message, allowing the recipient to verify its authenticity.

---

## Requirements

    Java JDK 8 or higher
    Bash shell

---

## Usage

### ***Starting the Server***

1. Navigate to the root directory of the project (a4).
2. Run the following command to start the server:

```bash
    ./startServer.sh <port_number>
```

>Replace <port_number> with the port number you want to use for the server.

NOTE: Any arguments inputted after the port number will be ignored.

Once you execute this command, you will be prompt if you would like to generate default certificates. Respond with either y or n.

```bash
    Do you want to generate default certificates? (y/n):
```

This default generation is only recommended for testing.

### ***Starting the Client***

1. Navigate to the root directory of the project (a4).
2. Run the following command to start the client:

```bash
    ./startClient.sh <host_name> <port_number>
```

>Replace <host_name> with the name of the host where the server is running, and <port_number> with the port number used by the server.

NOTE: Any arguments inputted after the port number will be ignored.

### ***Generating Default Certificates and Trust Store***

1. Navigate to the root directory of the project (a4).
2. Run the following command to generate default certificates and trust store:

```bash
    ./generateCertificatesAndTrustStore.sh
```
Once you execute this command, you will be prompt if you would like to generate default certificates. Respond with either y or n.

```bash
    Do you want to generate default certificates? (y/n):
```

This default generation is only recommended for testing.

### ***Cleaning the compiled files***

1. Navigate to the root directory of the project (a4).
2. Run the following command to clean all compiled files in the temp directory:

```bash
    ./clean.sh
```
---

### ***Client Usage***

The client will connect to the server through the secure channel and check the server for authenticity. Once connected to the server they will exchange keys,
one for symmetric encryption and the other for HMAC.

Once the client is started, the user would then be presented with a message to enter a username to connect to with the server. If the username is already connected, 
the client will be disconnected. If the user successfully connects, the server responds with CONNECT: OK, with is presented to the user.

Once connected, the client is presented with the following options:

1. GET
2. PUT
3. DELETE
4. DISCONNECT

To select one of these commands the user would enter the associated number corresponding to the command. If one of these options is not selected, the user is prompted to select again.

Following the selection of command the user must take the following action:

1. GET
   - Enter the associated key to get the value of.
2. PUT
   - Enter the associated key store the value.
   - Enter the associated value to store with the key.
3. DELETE
   - Enter the associated key to delete the key and value of. 
4. DISCONNECT
   - No action or data should follow the DISCONNECT command.

Following the users action the user is presented with the following server response:

1. GET
   - Associated value from the specified key
   - GET: ERROR
     - No associated was found
2. PUT
   - PUT: OK
     - Key value pair was successfully stored.
   - PUT: ERROR
     - Key value pair was not successfully stored.
3. DELETE
   - DELETE: OK
     - Key value pair was successfully deleted. This includes keys that do not exist.
   - DELETE: ERROR
     - Key value pair was not successfully deleted (remains stored).
4. DISCONNECT
   - DISCONNECT: OK
     - Server and client disconnect normally.

---

### ***Server Usage***

Once the server is started, it will await for clients to connect. Once a client connects through the secure channel they 
will exchange keys, one for symmetric encryption and the other for HMAC.

The server only accepts the following commands:

- CONNECT
  - Following the CONNECT command is the client ID / username.
- GET
  - Following the GET command is the associated key.
- PUT
  - Following the PUT command is a key, followed by a newline character, followed by the associated value.
- DELETE
  - Following the DELETE command is the associated key to delete.
- DISCONNECT
  - No data should follow the DISCONNECT command.

***It is important to note:***
- All completed commands must terminate with a new line character.
- Any other commands will result in disconnection of client.
- Only the client connections, disconnections and any errors are logged on the server. No other information is outputted.

---

## Constraints

### Timeout
If an error occurs from the server or a message is not received by the client within 30 seconds, the client connection will timeout. This means the client would disconnect from the server.

### Number of Clients
There is a maximum of 10 clients that can be connected to the server at any one time. Clients connecting when the server reaches maximum are placed into a queue until a client disconnects.

### Volatile Memory
All data stored in the server are stored in main memory and not in persistent memory, meaning all data is lost on voluntary/involuntary shutdown of server.

### Exhausted Memory
One Megabyte is server memory is reserved for normal operation. Any data attempting to be stored within the one Megabyte threshold of the maximum memory will not be executed into memory and will be dropped. 