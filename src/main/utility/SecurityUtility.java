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
    private static final String TRANSFORMATION = "AES";

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
     * @throws KeyStoreException If there is a problem with the key store.
     * @throws NoSuchAlgorithmException If the algorithm for creating a key manager or trust manager cannot be found.
     * @throws CertificateException If there is a problem with the certificate.
     * @throws IOException If there is an I/O problem with the file.
     * @throws UnrecoverableKeyException If the key cannot be recovered from the key store.
     * @throws KeyManagementException If there is a problem with the SSL context. 
     */
    public static SSLContext createSSLContext(final String keyStoreFileName, 
            final String trustStoreFileName, final char[] password, final SecureRandom secureRandom) 
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, 
            IOException, UnrecoverableKeyException, KeyManagementException {      
        
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
     * @throws NoSuchAlgorithmException If the encryption algorithm is not available.
     * @throws NoSuchPaddingException If the requested padding scheme is not available.
     * @throws InvalidKeyException If the specified key is invalid.
     * @throws IllegalBlockSizeException If the length of the input data is not a multiple of the block size.
     * @throws BadPaddingException If the input data is not padded properly.
     */
    public static byte[] encryptMessage(String message, Key key) 
            throws NoSuchAlgorithmException,  NoSuchPaddingException, 
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        
        // Creating a Cipher object
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        // Initialise Cipher object
        cipher.init(Cipher.ENCRYPT_MODE, key);

         // Encrypt data and return
        return cipher.doFinal(message.getBytes());
    }

    /**
     * Decrypts a message using the provided key.
     * @param message The encrypted message as a byte array.
     * @param key The secret key used to decrypt the message.
     * @return The decrypted message as a String.
     * @throws NoSuchAlgorithmException If the algorithm specified in TRANSFORMATION cannot be found.
     * @throws NoSuchPaddingException If the padding scheme specified in TRANSFORMATION is not available.
     * @throws InvalidKeyException If the provided key is invalid.
     * @throws IllegalBlockSizeException If the message size is not a multiple of the block size.
     * @throws BadPaddingException If the padding is invalid.
     */
    public static String decryptMessage(byte[] message, Key key) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, 
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        
        // Creating a Cipher object
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        // Initialise Cipher object
        cipher.init(Cipher.DECRYPT_MODE, key);

        // Decrypt message
        byte[] decryptMessageByte = cipher.doFinal(message);

        // Encode and return
        return new String(decryptMessageByte);
    }

    /**
     * Generates a MAC (Message Authentication Code) for the given message using the provided secret key.
     * @param message The message for which to generate the MAC.
     * @param key The secret key to use for generating the MAC.
     * @return A byte array representing the generated MAC.
     * @throws InvalidKeyException If the provided key is invalid.
     * @throws NoSuchAlgorithmException If the requested MAC algorithm is not available.
     */
    public static byte[] generateMac(final String message, final Key key) 
            throws InvalidKeyException, NoSuchAlgorithmException {
       
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
