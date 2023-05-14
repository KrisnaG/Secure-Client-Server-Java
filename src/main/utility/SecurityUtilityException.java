/**
 * @author Krisna Gusti
 */
package a4.src.main.utility;

/*
 * This class represents an exception that occurs when there is an error with the SecurityUtility class 
 * with the certificates, encryption, decryption, or MAC.
 */
public class SecurityUtilityException extends Exception {
    /**
     * Constructor.
     * @param message the error message associated with this exception.
     */
    public SecurityUtilityException(final String message) {
        super(message);
    }
}
