/**
 * @author Krisna Gusti
 */
package a4.src.main.server;

import a4.src.main.utility.Validation;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Server class that provides various services to the clients. It listens for incoming client 
 * connections and dispatches requests to the appropriate handler. The server uses a thread 
 * pool to manage concurrent requests.
 */
public class Server {
    private int portNumber;
    private static final ServerClientSessionManager serverClientIdManager = new ServerClientSessionManager();
    private static Logger logger = Logger.getLogger(Server.class.getName());
    
    /**
     * Constructor.
     * @param portNumber Port number for server.
     */
    public Server(final int portNumber) {
        this.portNumber = portNumber;
    }

    /**
     * Checks to see if enough memory is available to a given amount of bytes.
     * There are some reserved bytes to ensure normal operations.
     * @param bytes Number of bytes to be added to memory.
     * @return True if there is enough memory available, otherwise, false.
     */
    public static synchronized boolean isMemoryEnoughAvailable(final long bytes) {
        return Runtime.getRuntime().freeMemory() + bytes + ServerConstants.SERVER_RESERVED_BYTES
                < Runtime.getRuntime().maxMemory();
    }

    private SSLServerSocketFactory createSecureServerSocketFactory() {
        SSLServerSocketFactory sslServerSocketFactory = null;
        try {
            // load the keystore containing the server's certificate and private key
            KeyStore keyStore = KeyStore.getInstance("JKS");
            FileInputStream fileInputStream = new FileInputStream("src/main/server/resource/server.keystore");
            keyStore.load(fileInputStream, "password".toCharArray());

            // create a key manager factory to manage the server's key material
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "password".toCharArray());

            // create a trust manager factory to manage the server's trust store
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            // create an SSLContext to manage the SSL/TLS settings
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

            // create an SSLServerSocketFactory from the SSLContext
            sslServerSocketFactory = sslContext.getServerSocketFactory();

        } catch (Exception error) {
            logger.log(Level.WARNING, error.getMessage());
            System.exit(ServerConstants.EXIT_FAILURE_CONNECTION);
        } 

        return sslServerSocketFactory;
    }

    /**
     * Starts the server and listen for connections.
     */
    public void start() {
        // Executor to manage threads
        ExecutorService executor = Executors.newFixedThreadPool(ServerConstants.MAX_THREAD_COUNT);

        // Create an SSLServerSocketFactory
        SSLServerSocketFactory sslServerSocketFactory = this.createSecureServerSocketFactory();

        // Attempts to open port
        try (SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(this.portNumber)) {

            // configure the SSLServerSocket to require client authentication
            sslServerSocket.setNeedClientAuth(true);

            logger.log(Level.INFO, "PORT: {0} OPENED - SERVER READY", this.portNumber);

            while (true) {
                // Listens for incoming client connections
                SSLSocket clientSocket = (SSLSocket) sslServerSocket.accept();
                
                // Handle client in a separate thread
                ServerClientHandler clientHandler = new ServerClientHandler(clientSocket, serverClientIdManager);
                executor.submit(clientHandler);
            }
        } catch (Exception error) {
            logger.log(Level.WARNING, error.getMessage());
            System.exit(ServerConstants.EXIT_FAILURE_CONNECTION);
        } finally {
            // Shutdown thread manager
            executor.shutdown();
        }
    }

    /**
     * Entry point for the server application.
     * @param args an array of input arguments. Should contain the port number.
     */
    public static void main(String[] args) {

        // Validate input
        if (!Validation.validateInputs(args, ServerConstants.NUMBER_OF_SERVER_START_INPUTS)) {
            logger.log(Level.WARNING, ServerConstants.SERVER_USAGE);
            System.exit(Validation.EXIT_FAILURE_VALIDATION);
        }
        
        // Extract port number - This should be validated as integer already
        Server server = new Server(Integer.parseInt(args[0]));

        // Start sever
        server.start();
    }
}
