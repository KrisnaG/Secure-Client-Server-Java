/**
 * @author Krisna Gusti
 */
package a4.src.main.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import a4.src.main.utility.Commands;
import a4.src.main.utility.SecurityUtility;
import a4.src.main.utility.SecurityUtilityException;

/**
 * The ServerClientHandler class handles the communication with a single client connected to the server.
 * It extends the Thread class, allowing the handler to be run on a separate thread from the server.
 * 
 * The class receives messages from the client and executes commands based on the message content.
 * The following commands are supported:
 * - CONNECT: Connects the client to the server.
 * - GET: Retrieves data associated with a given key for the client.
 * - PUT: Stores data associated with a given key for the client.
 * - DELETE: Deletes data associated with a given key for the client.
 * - DISCONNECT: Disconnects the client from the server.
 */
public class ServerClientHandler implements Runnable {
    private final SSLSocket socket;
    private final ServerClientSessionManager serverClientSessionManager;
    private String clientID;
    private boolean clientConnected;
    private boolean disconnect;
    private SecretKey secretKey;
    private SecretKey macKey;
    private SecretKey sessionKey;
    private static Logger logger = Logger.getLogger(ServerClientHandler.class.getName());

    /**
     * Constructor.
     * @param socket The socket associated with the client connection.
     * @param serverClientSessionManager The session manager for handling the client's session.
     */
    public ServerClientHandler(SSLSocket socket, ServerClientSessionManager serverClientSessionManager) {
        this.socket = socket;
        this.serverClientSessionManager = serverClientSessionManager;
        this.clientID = null;
        this.clientConnected = false;
        this.disconnect = false;
    }

    /**
     * The main method for the thread.
     * Receives incoming messages from the client and executes the appropriate command.
     */
    @Override
    public void run() {
        try (
            PrintWriter serverOut = new PrintWriter(this.socket.getOutputStream(), true);
            BufferedReader serverIn = 
                new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
            ) {

            // Send and receive symmetric key - Sever sends first
            this.receiveSecretKeyFromClient(serverIn);
            this.sendSecretKeyToClient(serverOut);
            
            // Create a secret to encrypted stored data
            sessionKey = SecurityUtility.generateSecretKey(new SecureRandom());

            // Read incoming client messages
            while(!this.disconnect) {
                String clientRequest = this.waitAndGetRequestFromClient(serverIn);
                String[] inputTokens = clientRequest.split(" ", 2);
                Commands command = inputTokens.length > 0 ? Commands.fromString(inputTokens[0]) : Commands.UNKNOWN;
                String data = inputTokens.length > 1 ? inputTokens[1] : null;
                
                // All commands besides DISCONNECT must have associated data
                if ((!command.equals(Commands.DISCONNECT) && data == null) 
                    || (command.equals(Commands.DISCONNECT) && data != null)) {
                    this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
                    return;
                }

                // Execute client commands
                switch (command) {
                    case CONNECT:
                        this.handleConnect(serverOut, data);
                        break;
                    case DELETE:
                        this.handleDelete(serverOut, data);
                        break;
                    case DISCONNECT:
                        this.handleDisconnect(serverOut, true);
                        break;
                    case GET:
                        this.handleGet(serverOut, data);
                        break;
                    case PUT:
                        this.handlePut(serverOut, data);
                        break;
                    default:
                        // Invalid client command
                        logger.log(Level.WARNING, "Unknown client command");
                        this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
                        break;
                }
            }
        } catch (IOException | NoSuchAlgorithmException | SecurityUtilityException error) {
            logger.log(Level.WARNING, error.getMessage());
        } finally {
            // Ensure client data is remove if client unexpectedly disconnects
            this.serverClientSessionManager.disconnectClient(clientID);
            this.shutdown();
        }
    }

    /**
     * Generates a SecretKey, encodes it using Base64, and sends it to the client.
     * Assumes secure connect has been established.
     * @param serverOut The PrintWriter stream to send messages to the client.
     * @throws NoSuchAlgorithmException If the requested key algorithm is not available.
     */
    private void sendSecretKeyToClient(final PrintWriter serverOut) throws NoSuchAlgorithmException {
        // Generate SecretKey
        this.secretKey = SecurityUtility.generateSecretKey(new SecureRandom());
        
        // Convert the SecretKey to a byte array
        byte[] secretKeyBytes = secretKey.getEncoded();

        // Encode the byte array using Base64 and convert to a string
        String encodedSecretKey = Base64.getEncoder().encodeToString(secretKeyBytes);

        // Send the encoded SecretKey to the client
        serverOut.printf("%s%s", encodedSecretKey, ServerConstants.MESSAGE_TERMINATION );
    }

    /**
     * Receives an encoded SecretKey from the client, decodes it from Base64, and stores it as a SecretKey object.
     * Assumes secure connect has been established.
     * @param serverIn The BufferedReader stream to receive messages from the client.
     * @throws IOException If an I/O error occurs while reading the encoded SecretKey from the input stream.
     */
    private void receiveSecretKeyFromClient(final BufferedReader serverIn) throws IOException {
        // Receive the encoded SecretKey from the server
        String encodedSecretKey = serverIn.readLine();

        // Verify that the server's certificate is trusted by checking the SSLSession
        SSLSession sslSession = this.socket.getSession();
        sslSession.getPeerCertificates();

        // Decode the encoded SecretKey from Base64 to a byte array
        byte[] secretKeyBytes = Base64.getDecoder().decode(encodedSecretKey);

        // Convert the byte array to a SecretKey object
        this.macKey = new SecretKeySpec(secretKeyBytes, SecurityUtility.getKeyAlgorithm());
    }

    /**
     * Handles the CONNECT command from the client, which checks if the client is already connected
     * and loads client username.
     * @param serverOut The PrintWriter stream to send messages to the client.
     * @param data The client ID associated with the connection.
     * @throws SecurityUtilityException If there is an error during the encryption process.
     */
    private void handleConnect(final PrintWriter serverOut, final String data) throws SecurityUtilityException {
        // Check if client is already connected.
        if (!this.serverClientSessionManager.addClient(data)) {
            this.sendMessageToClient(
                serverOut, Commands.CONNECT.toString(), " ", ServerConstants.SERVER_ERROR);
            logger.log(Level.INFO, "CLIENT: {0} is already connected.", data);
            this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
            return;
        }

        this.clientID = data;
        this.clientConnected = true;
        this.sendMessageToClient(
            serverOut, Commands.CONNECT.toString(), " ", ServerConstants.SERVER_EXECUTED_COMMAND_OK);

        logger.log(Level.INFO, "CLIENT: {0} CONNECTED", data);
    }

    /**
     * Handles a DELETE command from the client, which deletes the data from data for the connected
     * client with the specified key.
     * @param serverOut The PrintWriter stream to send messages to the client.
     * @param key The key used to identify the data to be deleted.
     * @throws SecurityUtilityException If there is an error during the encryption process.
     */
    private void handleDelete(final PrintWriter serverOut, final String key) throws SecurityUtilityException {
        // Client must connect first
        if (!clientConnected) {
            this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
        }

        String deleteResponse = ServerConstants.SERVER_ERROR;

        // Encrypted key to delete
        String encryptedKey = Base64.getEncoder().encodeToString(
            SecurityUtility.encryptMessage(key, this.sessionKey));
        
        // Delete data and ensure its deleted
        if (this.serverClientSessionManager.deleteClientData(this.clientID, encryptedKey)) {
            deleteResponse = ServerConstants.SERVER_EXECUTED_COMMAND_OK;
        }

        this.sendMessageToClient(
                serverOut, Commands.DELETE.toString(), " ", deleteResponse);
    }

    /**
     * Disconnects the client, updates the server's client session manager, and closes the socket connection.
     * @param serverOut PrintWriter object used to send messages to the server
     * @param clientInitiatedDisconnect Indicates whether the client initiated the disconnection or not.
     * @throws SecurityUtilityException If there is an error during the encryption process.
     */
    private void handleDisconnect(final PrintWriter serverOut, final boolean clientInitiatedDisconnect) throws SecurityUtilityException {
        // Remove client data
        this.serverClientSessionManager.disconnectClient(clientID);
        this.clientConnected = false;
        this.disconnect = true;

        // Send disconnect message to client
        if (clientInitiatedDisconnect) {
            this.sendMessageToClient(
                serverOut, 
                Commands.DISCONNECT.toString(),
                " ",
                ServerConstants.SERVER_EXECUTED_COMMAND_OK);
        }
    }

    /**
     * Handles a GET command from the client, which retrieves data for the connected client 
     * with the specified key.
     * @param serverOut The PrintWriter used to send messages to the client.
     * @param key The key used to identify the data to be retrieved.
     * @throws SecurityUtilityException If there is an error during the encryption process.
     */
    private void handleGet(final PrintWriter serverOut, final String key) throws SecurityUtilityException {
        // Client must connect first
        if (!clientConnected) {
            this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
        }

        // Encrypted key to get
        String encryptedKey = Base64.getEncoder().encodeToString(
            SecurityUtility.encryptMessage(key, this.sessionKey));
        
        // Fetch data for client
        String encryptedClientData = this.serverClientSessionManager.getClientData(this.clientID, encryptedKey);
        
        // Check data is present
        if (encryptedClientData == null) {
            this.sendMessageToClient(serverOut, Commands.GET.toString(), " ", ServerConstants.SERVER_ERROR);
        } else {
            this.sendMessageToClient(
                serverOut, 
                SecurityUtility.decryptMessage(Base64.getDecoder().decode(encryptedClientData), this.sessionKey));
        }
    }

    /**
     * Handles a PUT command from the client, which adds or updates a key-value pair in the server's memory.
     * @param serverOut The PrintWriter used to send messages to the client.
     * @param key The key to be added or updated.
     * @param value The value to be added or updated.
     * @throws SecurityUtilityException If there is an error during the encryption process.
     */
    private void handlePut(final PrintWriter serverOut, final String data) throws SecurityUtilityException {
        // Extract the key and value
        String[] keyValuePair = data.split(String.valueOf(ServerConstants.MESSAGE_TERMINATION));
        
        // Encrypted key and value to store
        String encryptedKey = Base64.getEncoder().encodeToString(
            SecurityUtility.encryptMessage(keyValuePair[0], this.sessionKey));
        String encryptedValue = Base64.getEncoder().encodeToString(
           SecurityUtility.encryptMessage(keyValuePair[1], this.sessionKey));

        // Client must connect first
        if (!clientConnected) {
            this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
        }

        // Server must have enough memory to store data
        if (!Server.isMemoryEnoughAvailable((long) encryptedKey.getBytes().length + encryptedValue.getBytes().length)) {
            this.sendMessageToClient(serverOut, Commands.PUT.toString(), " ", ServerConstants.SERVER_ERROR);
        }
       
        // Put data and respond to the client
        if (this.serverClientSessionManager.putClientData(this.clientID, encryptedKey, encryptedValue)) {
            this.sendMessageToClient(
                serverOut, Commands.PUT.toString(), " ", ServerConstants.SERVER_EXECUTED_COMMAND_OK);
        } else {
            this.sendMessageToClient(
                serverOut, Commands.PUT.toString(), " ", ServerConstants.SERVER_ERROR);
        }      
    }
    
    /**
     * Sends a message to the client with its corresponding HMAC.
     * @param serverOut The PrintWriter stream to send the message to.
     * @param messages The message(s) to be sent to the client.
     * @throws SecurityUtilityException If there is an error during the encryption or MAC process.
     */
    private void sendMessageToClient(final PrintWriter serverOut, final String ... messages) throws SecurityUtilityException {
        // Join messages into one
        String message = String.join("", messages);
        System.out.println(message);
        // Compute HMAC for message using private key
        byte[] hmac = SecurityUtility.generateMac(message, this.macKey);

        // Encode HMAC to a string
        String encodedHmac = Base64.getEncoder().encodeToString(hmac);

        // Join original message and HMAC into a single message
        String jointMessage = message + ServerConstants.MESSAGE_TERMINATION + encodedHmac;

        // Encrypt data
        byte[] encryptedDataBytes = SecurityUtility.encryptMessage(jointMessage, this.secretKey);

        // Encode the encrypted data to a string to send to client
        String cipherText = Base64.getEncoder().encodeToString(encryptedDataBytes);

        // Send the cipher text to the client
        serverOut.printf("%s%s", cipherText, ServerConstants.MESSAGE_TERMINATION);
    }

    /**
     * Waits for a request from the client and returns the decrypted message.
     * @param serverIn The BufferedReader to read the message from the client.
     * @return The decrypted message.
     * @throws IOException If an I/O error occurs while waiting for the message from the client.
     * @throws SecurityUtilityException Uf there is an error during the decryption process.
     */
    private String waitAndGetRequestFromClient(final BufferedReader serverIn) throws IOException, SecurityUtilityException {
        // Read message in from server
        String receivedMessage = serverIn.readLine();

        // Decode the encoded message from Base64 to a byte array
        byte[] encryptedMessage = Base64.getDecoder().decode(receivedMessage);

        // Decrypt the message
        return SecurityUtility.decryptMessage(encryptedMessage, this.secretKey);
    }

    /**
     * Shuts down the client-server communication, closes the socket, and logs the status of the connection.
     */
    private void shutdown() {
        try {
             // Shutdown socket
            if (!this.socket.isClosed()) {
                this.socket.shutdownInput();
                this.socket.shutdownOutput();
                this.socket.close();
            }
        } catch (IOException error) {
            logger.log(Level.WARNING, error.getMessage());
        }

        if (this.clientID == null) {
            logger.log(Level.INFO, "CLIENT CONNECTION CLOSED");
        } else {
            logger.log(Level.INFO, "CONNECTION WITH {0} CLOSED & DATA REMOVED", this.clientID);
        }
    }
}
