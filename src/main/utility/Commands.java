/**
 * @author Krisna Gusti
 */
package a4.src.main.utility;

/**
 * The Commands enum represents the possible commands that the client can send to the server.
 */
public enum Commands {
    CONNECT("CONNECT"),
    PUT("PUT"),
    GET("GET"),
    DELETE("DELETE"),
    DISCONNECT("DISCONNECT"),
    UNKNOWN("UNKNOWN");

    private final String commandString;

    /**
     * Constructs a Commands object with the specified command string.
     * @param commandString the command string to be associated with this Commands object.
     */
    Commands(String commandString) {
        this.commandString = commandString;
    }

    /**
     * Returns the command string associated with this Commands object.
     * @return the command string associated with this Commands object.
     */
    public String getCommandString() {
        return commandString;
    }

    /**
     * Converts the command in String to enum.
     * @param commandString Command to convert.
     * @return the Commands enum associated with the specified command string if it is valid, otherwise, null.
     */
    public static Commands fromString(String commandString) {
        for (Commands command : Commands.values()) {
            if (command.getCommandString().equals(commandString)) {
                return command;
            }
        }
        return UNKNOWN;
    }
}
