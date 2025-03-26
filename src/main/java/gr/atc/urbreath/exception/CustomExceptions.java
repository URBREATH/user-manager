package gr.atc.urbreath.exception;

public class CustomExceptions {

    private CustomExceptions() {
    }

    public static class KeycloakException extends RuntimeException {
        public KeycloakException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static class DataRetrievalException extends RuntimeException {
        public DataRetrievalException(String message) {
            super(message);
        }
    }

    public static class InvalidActivationAttributesException extends RuntimeException {
        public InvalidActivationAttributesException(String message) {
            super(message);
        }
    }

    public static class InvalidResetTokenAttributesException extends RuntimeException {
        public InvalidResetTokenAttributesException(String message) {
            super(message);
        }
    }

    public static class InvalidAuthenticationCredentialsException extends RuntimeException {
        public InvalidAuthenticationCredentialsException(String message) {
            super(message);
        }
    }

    public static class ResourceAlreadyExistsException extends RuntimeException {
        public ResourceAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class UserActivateStatusException extends RuntimeException {
        public UserActivateStatusException(String message) {
            super(message);
        }
    }

}
