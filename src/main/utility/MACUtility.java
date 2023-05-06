/**
 * @author Krisna Gusti
 */

package a4.src.main.utility;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * The MACUtility class provides utility methods for generating and comparing message authentication codes (MACs) 
 * using the AES and HmacSHA256 algorithms.
 */
public class MACUtility {
    private static final String KEY_ALGORITHM = "AES";
    private static final String MAC_ALGORITHM = "HmacSHA256";

    /**
     *  This class is not meant to be instantiated
     */
    private MACUtility() {
        throw new IllegalStateException("Cannot instantiate ClientConstants class");
    }

    /**
     * Generates a new AES secret key using a KeyGenerator object initialized with a SecureRandom object.
     * @return A new SecretKey object representing the generated secret key.
     * @throws NoSuchAlgorithmException If the requested key algorithm is not available
     */
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        // Create a KeyGenerator object
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
       
        // Create a SecureRandom object
        SecureRandom secureRandom = new SecureRandom();
        
        // Initialise the KeyGenerator
        keyGenerator.init(secureRandom);
        
        // Generate a key
        return keyGenerator.generateKey();	
    }

    /**
     * Generates a MAC (Message Authentication Code) for the given message using the provided secret key.
     * @param message The message for which to generate the MAC.
     * @param key The secret key to use for generating the MAC.
     * @return A byte array representing the generated MAC.
     * @throws InvalidKeyException If the provided key is invalid.
     * @throws NoSuchAlgorithmException If the requested MAC algorithm is not available.
     */
    public static byte[] generateMac(final String message, final SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException {
        // Create a MAC with SHA256
        Mac mac = Mac.getInstance(MAC_ALGORITHM);

        // Initialise MAC with key
        mac.init(key);

        // Compute MAC and return digest
        byte[] messageBytes = message.getBytes();
        return mac.doFinal(messageBytes);
    }

    /**
     * Determines whether two given MAC codes are equal.
     * @param macOne The first MAC code to compare.
     * @param macTwo The second MAC code to compare.
     * @return true if the MAC codes are equal, false otherwise.
     */
    public static boolean macCodesAreEqual(final byte[] macOne, final byte[] macTwo) {
        if (macOne.length != macTwo.length) {
            return false;
        } else {
            for (int i = 0; i < macOne.length; i++) {
                if (macOne[i] != macTwo[i]) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Get the secret key algorithm used.
     * @return Secret key algorithm.
     */
    public static String getKeyAlgorithm() {
        return KEY_ALGORITHM;
    }

    /**
     * Get the MAC algorithm used.
     * @return MAC algorithm.
     */
    public static String getMacAlgorithm() {
        return MAC_ALGORITHM;
    }
}
