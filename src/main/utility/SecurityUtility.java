/**
 * @author Krisna Gusti
 */

package a4.src.main.utility;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * The SecurityUtility class provides methods for handling security related tasks 
 * such as SSL context creation, encryption, decryption, and MAC generation.
 */
public class SecurityUtility {
    private static final String PROTOCOL = "TLS";
    private static final String KEY_ALGORITHM = "AES";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    /**
     *  This class is not meant to be instantiated
     */
    private SecurityUtility() {
        throw new IllegalStateException("Cannot instantiate SecurityUtility class");
    }

    /**
     * Creates and returns an SSLContext with the given key store, trust store, password, and secure random.
     * @param keyStoreFileName The file name of the key store.
     * @param trustStoreFileName The file name of the trust store.
     * @param password The password to access the key store and trust store.
     * @param secureRandom The SecureRandom instance to use.
     * @return The SSLContext instance created.
     * @throws SecurityUtilityException If an error occurs while creating the SSLContext object
     */
    public static SSLContext createSSLContext(final String keyStoreFileName, final String trustStoreFileName, 
            final char[] password, final SecureRandom secureRandom) throws SecurityUtilityException {      
        try {
            // Load server keystore
            KeyStore serverKeyStore = KeyStore.getInstance("JKS");
            FileInputStream fileInputStream = new FileInputStream(keyStoreFileName);
            serverKeyStore.load(fileInputStream, password);     
            
            // Create a key manager factory to manage the server key
            KeyManagerFactory keyManagerFactory = 
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(serverKeyStore, password);       
        
            // Load server trust store
            KeyStore serverTrustStore = KeyStore.getInstance("JKS");
            FileInputStream serverTrustStoreFile = new FileInputStream(trustStoreFileName);
            serverTrustStore.load(serverTrustStoreFile, password);

            // Create a trust manager factory to manage the server trust store
            TrustManagerFactory trustManagerFactory = 
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(serverTrustStore);     
            
            // Create an SSLContext
            SSLContext sslContext = SSLContext.getInstance(PROTOCOL);
                sslContext.init(
                    keyManagerFactory.getKeyManagers(), 
                    trustManagerFactory.getTrustManagers(), 
                    secureRandom);      
            
            return sslContext;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException
                | IOException | UnrecoverableKeyException | KeyManagementException error) {
            throw new SecurityUtilityException("Unable to create SSL Context: " + error.getMessage());
        }
    }
    
    /**
     * Generates a new AES secret key using a KeyGenerator object initialized with a SecureRandom object.
     * @return A new SecretKey object representing the generated secret key.
     * @throws NoSuchAlgorithmException If the requested key algorithm is not available.
     */
    public static SecretKey generateSecretKey(SecureRandom secureRandom) throws NoSuchAlgorithmException {
        // Create a KeyGenerator object
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        
        // Initialise the KeyGenerator
        keyGenerator.init(secureRandom);
        
        // Generate a key
        return keyGenerator.generateKey();	
    }

    /**
     * Encrypts the given message using the specified key.
     * @param message The message to encrypt.
     * @param key The key to use for encryption.
     * @return The encrypted message as a byte array.
     * @throws SecurityUtilityException If there is an error during the encryption process.
     */
    public static byte[] encryptMessage(String message, Key key) throws SecurityUtilityException {
        try {
            // Creating a Cipher object
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);

            // Initialise Cipher object
            cipher.init(Cipher.ENCRYPT_MODE, key);

            // Encrypt data and return
        return cipher.doFinal(message.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException 
                | IllegalBlockSizeException | BadPaddingException error) {
            throw new SecurityUtilityException("Unable to encrypt message: " + error.getMessage());
        }
    }

    /**
     * Decrypts a message using the provided key.
     * @param message The encrypted message as a byte array.
     * @param key The secret key used to decrypt the message.
     * @return The decrypted message as a String.
     * @throws SecurityUtilityException If there is an error during the decryption process.
     */
    public static String decryptMessage(byte[] message, Key key) throws SecurityUtilityException {
        try {
            // Creating a Cipher object
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    
            // Initialise Cipher object
            cipher.init(Cipher.DECRYPT_MODE, key);
    
            // Decrypt message
            byte[] decryptMessageByte = cipher.doFinal(message);
    
            // Encode and return
            return new String(decryptMessageByte);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException 
                | IllegalBlockSizeException | BadPaddingException error) {
            throw new SecurityUtilityException("Unable to decrypt message: " + error.getMessage());
        }
    }

    /**
     * Generates a MAC (Message Authentication Code) for the given message using the provided secret key.
     * @param message The message for which to generate the MAC.
     * @param key The secret key to use for generating the MAC.
     * @return A byte array representing the generated MAC.
     * @throws SecurityUtilityException If there is an error during the MAC process.
     */
    public static byte[] generateMac(final String message, final Key key) throws SecurityUtilityException {
       
        try {
            // Create a MAC with SHA256
            Mac mac = Mac.getInstance(MAC_ALGORITHM);

            // Initialise MAC with key
            mac.init(key);

            // Compute MAC and return digest
            byte[] messageBytes = message.getBytes();
            return mac.doFinal(messageBytes);
        } catch (InvalidKeyException | NoSuchAlgorithmException error) {
            throw new SecurityUtilityException("Unable to generate MAC: " + error.getMessage());
        }

    }

    /**
     * Determines whether two given MAC codes are equal.
     * @param macOne The first MAC code to compare.
     * @param macTwo The second MAC code to compare.
     * @return True if the MAC codes are equal, false otherwise.
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
     * Get the key algorithm used.
     * @return Key algorithm.
     */
    public static String getKeyAlgorithm() {
        return KEY_ALGORITHM;
    }
}
