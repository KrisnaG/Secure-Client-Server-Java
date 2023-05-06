/**
 * @author Krisna gusti
 */
package a4.src.main.client;

import a4.src.main.utility.Validation;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * The Client class represents a client that connects to a server.
 */
public class Client {
    private final String hostName;
    private final int portNumber;
    private static Logger logger = Logger.getLogger(Client.class.getName());
    private final char[] password = "password".toCharArray();

    /**
     * Constructs a new Client with the given host name and port number.
     * @param hostName the host name of the server to connect to.
     * @param portNumber the port number to use for the connection.
     */
    public Client(final String hostName, final int portNumber) {
        this.hostName = hostName;
        this.portNumber = portNumber;
    }

    private SSLSocketFactory createSecureSocketFactory() {
        SSLSocketFactory sslSocketFactory = null;
        try {
            // Load client keystore
            KeyStore clientKeyStore = KeyStore.getInstance("JKS");
            FileInputStream clientKeyStoreFile = new FileInputStream("src/main/client/resource/client.keystore");
            clientKeyStore.load(clientKeyStoreFile, password);
    
            // Load client truststore
            KeyStore clientTrustStore = KeyStore.getInstance("JKS");
            FileInputStream clientTrustStoreFile = new FileInputStream("src/main/resource/truststore.jks");
            clientTrustStore.load(clientTrustStoreFile, password);
    
            // Create SSL context
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(clientTrustStore);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(clientKeyStore, password);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
    
            // Create an SSLSocketFactory from the SSLContext
            sslSocketFactory = sslContext.getSocketFactory();    
        } catch (Exception error) {
            logger.log(Level.WARNING, error.getMessage());
            logger.log(Level.INFO, "Shutting down");
            System.exit(2);
        }

        return sslSocketFactory;
    }

    /**
     * Attempts to connect to the specified host and port, and executes user commands with the server.
     */
    public void connectToHost() {
        SSLSocketFactory sslSocketFactory = this.createSecureSocketFactory();

        // Attempts to connect to host on given port
        try (
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(this.hostName, this.portNumber);
            PrintWriter clientOut = new PrintWriter(sslSocket.getOutputStream(), true);
            BufferedReader clientIn = 
                new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
            Scanner scanner = new Scanner(System.in);
            ) {
            boolean disconnect = false;
            
            // Set timeout to prevent client hanging if server never responds
            sslSocket.setSoTimeout(ClientConstants.MAX_TIMEOUT_MILLISECONDS);

            // Start connecting with serve
            sslSocket.startHandshake();

            // Verify that the server's certificate is trusted by checking the SSLSession
            SSLSession sslSession = sslSocket.getSession();
            sslSession.getPeerCertificates();

            // For user handling
            ClientUserHandling clientUserHandling = new ClientUserHandling(sslSocket, clientIn, clientOut, scanner);

            // Connect to server with username
            clientUserHandling.handleConnect();

            // Execute user commands with Server
            while (!disconnect) {
                disconnect = clientUserHandling.handleRequest();
            }
        } catch (SSLPeerUnverifiedException error) {
            logger.log(Level.WARNING, error.getMessage());
            logger.log(Level.INFO, "Untrusted Server Certificate - Disconnecting");
        } catch (UnknownHostException | SocketTimeoutException | ClientException error) {
            logger.log(Level.WARNING, error.getMessage());
            logger.log(Level.INFO, "Disconnecting");
        }  catch (IOException error) {
            logger.log(Level.WARNING, error.getMessage());
            logger.log(Level.INFO, "IO Error - Disconnecting");
        }
    }

    /**
     * Entry point for the client application.
     * @param args an array of input arguments. Should contain the host name and port number.
     */
    public static void main(String[] args) {
        // Validate inputs
        if (!Validation.validateInputs(args, ClientConstants.NUMBER_OF_CLIENT_START_INPUTS)) {
            logger.log(Level.WARNING, ClientConstants.CLIENT_USAGE);
            System.exit(Validation.EXIT_FAILURE_VALIDATION);
        }
       
        // Create client - Inputs should be  already validated
        Client client = new Client(args[0], Integer.parseInt(args[1]));

        // Connect to host
        client.connectToHost();
    }
}
