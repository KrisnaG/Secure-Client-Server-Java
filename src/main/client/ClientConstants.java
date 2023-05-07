/**
 * @author Krisna Gusti
 */
package a4.src.main.client;

/**
 * This class contains constants used in the client application.
 */
public class ClientConstants {
    /**
     *  This class is not meant to be instantiated
     */
    private ClientConstants() {
        throw new IllegalStateException("Cannot instantiate ClientConstants class");
    }

    // Client inputs
    public static final int NUMBER_OF_CLIENT_START_INPUTS = 2;

    // Client timeout
    public static final int MAX_TIMEOUT_MILLISECONDS = 30_000;
    
    // File locations
    public static final String CLIENT_KEYSTORE_FILENAME = "src/main/client/resource/client.keystore";
    public static final String TRUST_STORE_FILENAME = "src/main/resource/truststore.jks";

    // Client/Server message
    public static final char MESSAGE_TERMINATION = '\n';
    public static final String CLIENT_CONNECT = "CONNECT";
    public static final String CLIENT_OK = "OK";
    public static final String CLIENT_ERROR = "ERROR";
    
    // User messages
    public static final String CLIENT_USAGE = "Usage: ./startClient <hostname> <port number>";
    public static final String CLIENT_USER_CONNECT_MESSAGE = "Enter username: ";
    public static final String CLIENT_USER_COMMAND_MESSAGE = "\nAvailable options (Use the associated number):\n"
                                                           + "1. GET\n"
                                                           + "2. PUT\n"
                                                           + "3. DELETE\n"
                                                           + "4. DISCONNECT\n";
    public static final String CLIENT_USER_GET_MESSAGE = "Please enter a key for the GET request: ";
    public static final String CLIENT_USER_DELETE_MESSAGE = "Please enter a key for the DELETE request: ";
    public static final String CLIENT_USER_PUT_KEY_MESSAGE = "Please enter a key for the PUT request: ";
    public static final String CLIENT_USER_PUT_VALUE_MESSAGE = "Please enter the data: ";
    public static final String INVALID_KEY_ERROR = "Invalid key";
    public static final String INVALID_VALUE_ERROR = "Invalid value";

    // Server response error
    public static final String INVALID_NULL_RESPONSE_ERROR = "Server Response NULL";
    public static final String INVALID_CONNECT_RESPONSE_ERROR = "Invalid CONNECT Server Response";
    public static final String INVALID_CONNECT_ERROR = "Server Connection Error";
    public static final String INVALID_PUT_RESPONSE_ERROR = "Invalid PUT Server Response";
    public static final String INVALID_DELETE_RESPONSE_ERROR = "Invalid DELETE Server Response";
    public static final String INVALID_DISCONNECT_RESPONSE_ERROR = "Invalid DISCONNECT Server Response";
}
