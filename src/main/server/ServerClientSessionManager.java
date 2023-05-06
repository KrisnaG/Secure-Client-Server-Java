/**
 * @author Krisna Gusti
 */
package a4.src.main.server;

import java.util.Map;
import java.util.HashMap;

/**
 * Manages the session data for clients connected to the server.
 */
public class ServerClientSessionManager {
    // Map to store session data for clients
    private static final Map<String, Map<String, String>> clientSession = new HashMap<>();

    /**
     * Adds a new client to the session.
     * @param clientId The ID of the client to add.
     * @return True if the client was added, false otherwise.
     */
    public synchronized boolean addClient(String clientId) {
        if (clientId == null || clientSession.containsKey(clientId)) {
            return false;
        }
        clientSession.put(clientId, new HashMap<>());
        return true;
    }

    /**
     * Disconnects a client from the session by removing all client data.
     * @param clientId The ID of the client to disconnect.
     */
    public synchronized void disconnectClient(String clientId) {
        if (clientId != null && clientSession.containsKey(clientId)) {
            clientSession.remove(clientId);
        }
    }

    /**
     * Gets the value associated with a key for a client in the session.
     * @param clientId The ID of the client.
     * @param key The key for the value to retrieve.
     * @return The value associated with the key for the client, or null if the client or key is not found.
     */
    public synchronized String getClientData(String clientId, String key) {
        return clientSession.get(clientId).get(key);
    }

    /**
     * Puts the value associated with a key for a client in the session.
     * @param clientId The ID of the client.
     * @param key The key for the value to set.
     * @param value The value to set.
     * @return True if key specified is mapped, otherwise, false.
     */
    public synchronized boolean putClientData(String clientId, String key, String value) {
        if (clientSession.get(clientId).containsKey(key)) {
            return clientSession.get(clientId).put(key, value) != null;
        } else {
            return clientSession.get(clientId).put(key, value) == null;
        }
    }


    /**
     * Deletes the value associated with a key for a client in the session.
     * @param clientId The ID of the client.
     * @param key The key for the value to delete.
     * @return True if key was successfully removed, otherwise, false.
     */
    public synchronized boolean deleteClientData(String clientID, String key) {
        clientSession.get(clientID).remove(key);
        return clientSession.get(clientID).get(key) == null;
    }
}
