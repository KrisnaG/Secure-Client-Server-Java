/**
 * @author Krisna Gusti
 */
package a4.src.main.client;

/*
 * This class represents an exception that occurs when there is an error with the client.
 */
public class ClientException extends Exception {
    /**
     * Constructor.
     * @param message the error message associated with this exception.
     */
    public ClientException(final String message) {
        super(message);
    }
}
