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

public class MACUtility {
    /**
     *  This class is not meant to be instantiated
     */
    private MACUtility() {
        throw new IllegalStateException("Cannot instantiate ClientConstants class");
    }

    /**
     * 
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        // Create a KeyGenerator object
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
       
        // Create a SecureRandom object
        SecureRandom secureRandom = new SecureRandom();
        
        // Initialise the KeyGenerator
        keyGenerator.init(secureRandom);
        
        // Generate a key
        return keyGenerator.generateKey();	
    }

    /**
     * 
     * @param message
     * @param key
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] generateMac(final String message, final SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException {
        // Create a MAC with SHA256
        Mac mac = Mac.getInstance("HmacSHA256");

        // Initialise MAC with key
        mac.init(key);

        // Compute MAC and return digest
        byte[] messageBytes = message.getBytes();
        return mac.doFinal(messageBytes);
    }

    /**
     * 
     * @param macOne
     * @param macTwo
     * @return
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
}
