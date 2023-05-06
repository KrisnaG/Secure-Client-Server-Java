/**
 * @author Krisna Gusti
 */
package a4.src.main.client;

import a4.src.main.utility.Commands;
import a4.src.main.utility.MACUtility;
import a4.src.main.utility.Validation;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * A class that handles user input and communication with the server.
 */
public class ClientUserHandling {
    private final SSLSocket sslSocket;
    private final BufferedReader clientIn;
    private final PrintWriter clientOut;
    private final Scanner scanner;
    private boolean disconnectFromServer;
    private SecretKey secretKey;
    
    /**
     * Constructor.
     * @param clientIn the input stream of the client's socket.
     * @param clientOut the output stream of the client's socket.
     * @param scanner the scanner to read input from the console.
     */
    public ClientUserHandling(final SSLSocket sslSocket, final BufferedReader clientIn, 
            final PrintWriter clientOut, final Scanner scanner) {
        this.sslSocket = sslSocket;
        this.clientIn = clientIn;
        this.clientOut = clientOut;
        this.scanner = scanner;
        disconnectFromServer = false;
    }

    /**
     * Receives a SecretKey object from the server, encoded in Base64 format.
     * Verifies that the server's certificate is trusted and then decodes the
     * SecretKey from Base64 format and converts it to a SecretKey object.
     * @throws IOException If an I/O error occurs while reading the encoded SecretKey from the input stream.
     */
    protected void receiveSecretKeyFromServer() throws IOException {
        // Receive the encoded SecretKey from the server
        String encodedSecretKey = this.clientIn.readLine();

        // Verify that the server's certificate is trusted by checking the SSLSession
        SSLSession sslSession = sslSocket.getSession();
        sslSession.getPeerCertificates();

        // Decode the encoded SecretKey from Base64 to a byte array
        byte[] secretKeyBytes = Base64.getDecoder().decode(encodedSecretKey);

        // Convert the byte array to a SecretKey object
        this.secretKey = new SecretKeySpec(secretKeyBytes, MACUtility.getKeyAlgorithm());
    }

    /**
     * Handles the connection of the client to the server. It prompts the user to input 
     * their username, connects to the server with the username, waits for a response 
     * from the server, and then validates the response.
     * @throws IOException if there is an error with the input/output stream.
     * @throws ClientException if there is an error with the server response.
     * @throws InvalidKeyException If the secret key is invalid for computing the MAC.
     * @throws NoSuchAlgorithmException If the algorithm for computing the MAC is not available.
     */
    protected void handleConnect() throws IOException, ClientException, InvalidKeyException, 
            NoSuchAlgorithmException {
        // Get user input
        System.out.print(ClientConstants.CLIENT_USER_CONNECT_MESSAGE);
        String userInput = this.getUserInput();

        // Connect to server with username
        this.sendMessageToServer(ClientConstants.CLIENT_CONNECT, " ", userInput);
        
        // Wait for server response
        String response = getAndCheckMessageFromServer();

        // Ensure response is not null
        if (response == null) {
            throw new ClientException(ClientConstants.INVALID_NULL_RESPONSE_ERROR);
        }

        String[] responseToken = response.split(" ", 2);

        // Check if server response has two parts
        if (!Validation.numberOfInputsValid(responseToken, 2)) {
            throw new ClientException(ClientConstants.INVALID_CONNECT_RESPONSE_ERROR);
        }

        // Error response received from server
        if (responseToken[1].equals(ClientConstants.CLIENT_ERROR)) {
            throw new ClientException(ClientConstants.INVALID_CONNECT_ERROR);
        }
        
        // Check server response is valid
        if (!responseToken[0].equals(Commands.CONNECT.toString()) || 
            !responseToken[1].equals(ClientConstants.CLIENT_OK)) {
                throw new ClientException(ClientConstants.INVALID_CONNECT_RESPONSE_ERROR);
        }

        // Display server response
        System.out.println(response);
    }

    /**
     * Handles user requests by prompting the user for input, parsing the input,
     * and calling the appropriate handler method.
     * @throws IOException if there is an error with the input/output stream.
     * @throws ClientException if there is an error with the server response.
     * @return true if the user wishes to disconnect, otherwise, false.
     * @throws InvalidKeyException If the secret key is invalid for computing the MAC.
     * @throws NoSuchAlgorithmException If the algorithm for computing the MAC is not available.
     */
    protected boolean handleRequest() throws IOException, ClientException, InvalidKeyException,
            NoSuchAlgorithmException {        
        // Get user command
        System.out.print(ClientConstants.CLIENT_USER_COMMAND_MESSAGE);
        String userInput = this.getUserInput();

        // Executes user command
        switch (userInput) {
            case "1":
                this.handleGet();
                break;
            case "2":
                this.handlePut();
                break;
            case "3":
                this.handleDelete();
                break;
            case "4":
                this.handleDisconnect();
                break;
            default:
                System.out.println("Unknown user command! Please try again.");
                break;
        }
        
        return this.disconnectFromServer;
    }

    /**
     * Handles the GET command by getting the key from the user, sending a GET 
     * request with the key to the server, waiting for the server response, and 
     * printing it to the console.
     * @throws IOException if there is an error with the input/output stream.
     * @throws ClientException if there is an error with the client response.
     * @throws InvalidKeyException If the secret key is invalid for computing the MAC.
     * @throws NoSuchAlgorithmException If the algorithm for computing the MAC is not available.
     */
    private void handleGet() throws IOException, ClientException, InvalidKeyException, NoSuchAlgorithmException {
        // Get key from user
        System.out.println(ClientConstants.CLIENT_USER_GET_MESSAGE);
        String key = this.getUserInput();

        // Check for valid key
        if (key == null || key.equals("")) {
            System.out.println(ClientConstants.INVALID_KEY_ERROR);
            return;
        }

        // Send GET request with key to server
        this.sendMessageToServer(Commands.GET.toString(), " ", key);

        // Wait for server response
        String response = getAndCheckMessageFromServer();

        // Ensure response is not null
        if (response == null) {
            throw new ClientException(ClientConstants.INVALID_NULL_RESPONSE_ERROR);
        }        

        System.out.println(response);
    }

    /**
     * Handles the DELETE command by getting a key from the user, sending a DELETE
     * request with the key to the server, waiting for the server response, and 
     * printing the response to the console.
     * @throws IOException if there is an error with the input/output stream.
     * @throws ClientException if there is an error with the client response.
     * @throws InvalidKeyException If the secret key is invalid for computing the MAC.
     * @throws NoSuchAlgorithmException If the algorithm for computing the MAC is not available.
     */
    private void handleDelete() throws IOException, ClientException, InvalidKeyException, NoSuchAlgorithmException {
        // Get key from user
        System.out.println(ClientConstants.CLIENT_USER_DELETE_MESSAGE);
        String key = this.getUserInput();

        // Check for valid key
        if (key == null || key.equals("")) {
            System.out.println(ClientConstants.INVALID_KEY_ERROR);
            return;
        }

        // Send DELETE request with key to server
        this.sendMessageToServer(Commands.DELETE.toString(), " ", key);

        // Wait for server response
        String response = getAndCheckMessageFromServer();

        // Ensure response is not null
        if (response == null) {
            throw new ClientException(ClientConstants.INVALID_NULL_RESPONSE_ERROR);
        }

        String[] responseToken = response.split(" ", 2);

        // Test Server response is valid
        if (!responseToken[0].equals(Commands.DELETE.toString()) || 
            (!responseToken[1].equals(ClientConstants.CLIENT_OK) && 
            !responseToken[1].equals(ClientConstants.CLIENT_ERROR))) {
                throw new ClientException(ClientConstants.INVALID_DELETE_RESPONSE_ERROR);
        }

        // Print server response
        System.out.println(response);
    }

    /**
     * Sends a DISCONNECT command to the server and waits for its response.
     * @throws IOException if there is an error with the input/output stream.
     * @throws ClientException if there is an error with the client response.
     * @throws InvalidKeyException If the secret key is invalid for computing the MAC.
     * @throws NoSuchAlgorithmException If the algorithm for computing the MAC is not available.
     */
    private void handleDisconnect() throws IOException, ClientException, InvalidKeyException, NoSuchAlgorithmException {
        // Send DISCONNECT request to server
        this.sendMessageToServer(Commands.DISCONNECT.toString());

        // Wait for server response
        String response = getAndCheckMessageFromServer();

        // Ensure response is not null
        if (response == null) {
            throw new ClientException(ClientConstants.INVALID_NULL_RESPONSE_ERROR);
        }

        String[] responseToken = response.split(" ");

        // Test Server response is valid
        if (!responseToken[0].equals(Commands.DISCONNECT.toString()) || 
            !responseToken[1].equals(ClientConstants.CLIENT_OK)) {
                throw new ClientException(ClientConstants.INVALID_DISCONNECT_RESPONSE_ERROR);
        }

        // Print server response
        System.out.println(response);

        // Disconnect from server gracefully
        this.disconnectFromServer = true;
    }

    /**
     * Handles the PUT command by getting key and value from the user, sending a
     * PUT request with the key and value to the server, and waiting for the server
     * response.
     * @throws IOException if there is an error with the input/output stream.
     * @throws ClientException if there is an error with the client response.
     * @throws InvalidKeyException If the secret key is invalid for computing the MAC.
     * @throws NoSuchAlgorithmException If the algorithm for computing the MAC is not available.
     */
    private void handlePut() throws IOException, ClientException, InvalidKeyException, NoSuchAlgorithmException {
        // Get key from user
        System.out.println(ClientConstants.CLIENT_USER_PUT_KEY_MESSAGE);
        String key = this.getUserInput();

        // Check for valid key
        if (key == null || key.equals("")) {
            System.out.println(ClientConstants.INVALID_KEY_ERROR);
            return;
        }

        // Get key from user
        System.out.println(ClientConstants.CLIENT_USER_PUT_VALUE_MESSAGE);
        String value = this.getUserInput();

        // Check for valid value
        if (value == null || value.equals("")) {
            System.out.println(ClientConstants.INVALID_VALUE_ERROR);
            return;
        }

        // Send PUT request with key to server
        this.sendMessageToServer(Commands.PUT.toString(), " ", key, 
            String.valueOf(ClientConstants.MESSAGE_TERMINATION), value);

        // Wait for server response
        String response = getAndCheckMessageFromServer();

        // Ensure response is not null
        if (response == null) {
            throw new ClientException(ClientConstants.INVALID_NULL_RESPONSE_ERROR);
        }

        String[] responseToken = response.split(" ", 2);

        // Test Server response is valid
        if (!responseToken[0].equals(Commands.PUT.toString()) || 
            (!responseToken[1].equals(ClientConstants.CLIENT_OK) && 
            !responseToken[1].equals(ClientConstants.CLIENT_ERROR))) {
                throw new ClientException(ClientConstants.INVALID_PUT_RESPONSE_ERROR);
        }
        
        // Print server response
        System.out.println(response);
    }

    /**
     * Sends a message to the server.
     * @param messages The message(s) to be sent to the server.
     */
    private void sendMessageToServer(final String ... messages) {
        String message = String.join("", messages);
        this.clientOut.printf("%s%s", message, ClientConstants.MESSAGE_TERMINATION);
    }

    /**
     * Reads a line of input from the user and removes any trailing newline characters.
     * @return The user input string.
     */
    private String getUserInput() {
        // Get user input
        String userInput = this.scanner.nextLine();
        
        // Remove any newline characters from end
        userInput = userInput.endsWith("\n") ? userInput.substring(0, userInput.length() - 1) : userInput;

        return userInput;
    }

    /**
     * Receives an encoded HMAC and a message from the server, decodes and verifies the HMAC,
     * and returns the message if the verification is successful.
     * @return Ihe message received from the server.
     * @throws IOException if there is an error with the input/output stream.
     * @throws InvalidKeyException If the secret key is invalid for computing the MAC.
     * @throws NoSuchAlgorithmException If the algorithm for computing the MAC is not available.
     * @throws SecurityException If the received HMAC does not match the computed HMAC for the message, 
     * indicating that the message has been tampered with.
     */
    private String getAndCheckMessageFromServer() throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        // Receive the encoded SecretKey from the server
        String encodedHmac = this.clientIn.readLine();

        // Decode the encoded HMAC from Base64 to a byte array
        byte[] receievedHmac = Base64.getDecoder().decode(encodedHmac);

        // Receive the encoded HMAC from the server
        String message = this.clientIn.readLine();

        byte[] messageHmac = MACUtility.generateMac(message, this.secretKey);

        if (MACUtility.macCodesAreEqual(messageHmac, receievedHmac)) {
            return message;
        } else {
            throw new SecurityException("HMAC verification failed - Message has been tampered with.");
        }
    }
}
