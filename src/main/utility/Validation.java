/**
 * @author Krisna Gusti
 */
package a4.src.main.utility;

/**
 * Validation class to validate inputs.
 */
public class Validation {
    public static final int EXIT_FAILURE_VALIDATION = 1;

    /**
     *  This class is not meant to be instantiated
     */
    private Validation() {
        throw new IllegalStateException("Cannot instantiate ClientConstants class");
    }

    /**
     * Checks the input string array for valid length and valid number.
     * The argument in the array should be a number.
     * @param input String array of arguments to be checked.
     * @param numberOfInputs The length the array should be.
     * @return True if valid, otherwise, false.
     */
    public static boolean validateInputs(final String[] input, final int numberOfInputs) {
        return Validation.numberOfInputsValid(input, numberOfInputs) 
            && Validation.isInputAValidNumber(input[input.length - 1]);
    }

    /**
     * Checks if the number of inputs.
     * @param arguments String array of arguments to check.
     * @param numberOfInputs The length the array should be.
     * @return True if valid, otherwise, false.
     */
    public static boolean numberOfInputsValid(final String[] arguments, final int numberOfInputs) {
        return arguments.length == numberOfInputs;
    }

    /**
     * Checks if the String input is a valid number.
     * @param input String to check.
     * @return True if valid, otherwise, false.
     */
    public static boolean isInputAValidNumber(final String input) {
        try {
            Integer.parseInt(input);
            return true;
        } catch (NumberFormatException error) {
            return false;
        }
    }
}
