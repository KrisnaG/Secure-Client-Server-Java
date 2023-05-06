/**
 * @author Krisna Gusti
 */
package a4.src.main.server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;

import a4.src.main.utility.Commands;

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

            // Read incoming client messages
            while(!this.disconnect) {
                String[] inputTokens = serverIn.readLine().split(" ", 2);
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
                        this.handlePut(serverOut, data, serverIn.readLine());
                        break;
                    default:
                        // Invalid client command
                        logger.log(Level.WARNING, "Unknown client command");
                        this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
                        break;
                }
            }
        } catch (IOException error) {
            logger.log(Level.WARNING, error.getMessage());
        } finally {
            // Ensure client data is remove if client unexpectedly disconnects
            this.serverClientSessionManager.disconnectClient(clientID);
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

    /**
     * Handles the CONNECT command from the client, which checks if the client is already connected
     * and loads client username.
     * @param serverOut The PrintWriter stream to send messages to the client.
     * @param data The client ID associated with the connection.
     * @throws IOException If there is an I/O error while sending or receiving data from the client.
     */
    public void handleConnect(final PrintWriter serverOut, final String data) throws IOException {
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
     * @throws IOException If there is an I/O error while sending or receiving data from the client.
     */
    public void handleDelete(final PrintWriter serverOut, final String key) throws IOException {
        // Client must connect first
        if (!clientConnected) {
            this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
        }

        String deleteResponse = ServerConstants.SERVER_ERROR;
        
        // Delete data and ensure its deleted
        if (this.serverClientSessionManager.deleteClientData(this.clientID, key)) {
            deleteResponse = ServerConstants.SERVER_EXECUTED_COMMAND_OK;
        }

        this.sendMessageToClient(
                serverOut, Commands.DELETE.toString(), " ", deleteResponse);
    }

    /**
     * Disconnects the client, updates the server's client session manager, and closes the socket connection.
     * @param serverOut PrintWriter object used to send messages to the server
     * @param clientInitiatedDisconnect Indicates whether the client initiated the disconnection or not.
     * @throws IOException if there is an I/O error while closing the socket connection
     */
    public void handleDisconnect(final PrintWriter serverOut, final boolean clientInitiatedDisconnect) 
            throws IOException {
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
    * @throws IOException If an I/O error occurs while communicating with the client or server.
    */
    public void handleGet(final PrintWriter serverOut, final String key) throws IOException {
        // Client must connect first
        if (!clientConnected) {
            this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
        }
        
        // Fetch data for client
        String clientData = this.serverClientSessionManager.getClientData(this.clientID, key);
        
        // Check data is present
        if (clientData == null) {
            this.sendMessageToClient(serverOut, Commands.GET.toString(), " ", ServerConstants.SERVER_ERROR);
        } else {
            this.sendMessageToClient(serverOut, clientData);
        }
    }

    /**
     * Handles a PUT command from the client, which adds or updates a key-value pair in the server's memory.
     * @param serverOut The PrintWriter used to send messages to the client.
     * @param key The key to be added or updated.
     * @param value The value to be added or updated.
     * @throws IOException if there is an error sending messages to the client or closing the socket.
     */
    public void handlePut(final PrintWriter serverOut, final String key, final String value) throws IOException {
        // Client must connect first
        if (!clientConnected) {
            this.handleDisconnect(serverOut, ServerConstants.SERVER_DISCONNECT_ERROR);
        }

        // Server must have enough memory to store data
        if (!Server.isMemoryEnoughAvailable((long) key.getBytes().length + value.getBytes().length)) {
            this.sendMessageToClient(serverOut, Commands.PUT.toString(), " ", ServerConstants.SERVER_ERROR);
        }
       
        // Put data and respond to the client
        if (this.serverClientSessionManager.putClientData(this.clientID, key, value)) {
            this.sendMessageToClient(
                serverOut, Commands.PUT.toString(), " ", ServerConstants.SERVER_EXECUTED_COMMAND_OK);
        } else {
            this.sendMessageToClient(
                serverOut, Commands.PUT.toString(), " ", ServerConstants.SERVER_ERROR);
        }      
    }
    
    /**
     * Sends a message to the client.
     * @param serverOut The PrintWriter stream to send the message to.
     * @param messages The message(s) to be sent to the client.
     */
    public void sendMessageToClient(final PrintWriter serverOut, final String ... messages) {
        String message = String.join("", messages);
        serverOut.printf("%s%s", message, ServerConstants.MESSAGE_TERMINATION);
    }
}
