/**
 * @author Krisna Gusti
 */
package a4.src.main.server;

/**
 * This class contains constants used in the server application.
 */
public class ServerConstants {
    /**
     *  This class is not meant to be instantiated
     */
    private ServerConstants() {
        throw new IllegalStateException("Cannot instantiate ServerConstants class");
    }

    // Server error codes
    public static final int EXIT_FAILURE_CONNECTION = 1;
    public static final boolean SERVER_DISCONNECT_ERROR = false;

    // Server threads
    public static final int MAX_THREAD_COUNT = 10;

    // Server reserved memory in bytes
    public static final long SERVER_RESERVED_BYTES = 1_048_576;

    // Server inputs
    public static final int NUMBER_OF_SERVER_START_INPUTS = 1;

    // File locations
    public static final String SERVER_KEYSTORE_FILENAME = "src/main/server/resource/server.keystore";
    public static final String TRUST_STORE_FILENAME = "src/main/resource/truststore.jks";

    // Server messages
    public static final char MESSAGE_TERMINATION = '\n';
    public static final String SERVER_USAGE = "Usage: ./startServer <port number>";
    public static final String SERVER_EXECUTED_COMMAND_OK = "OK";
    public static final String SERVER_ERROR = "ERROR";    
}
