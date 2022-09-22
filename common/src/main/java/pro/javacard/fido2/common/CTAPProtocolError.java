package pro.javacard.fido2.common;

public class CTAPProtocolError extends RuntimeException {

    public CTAPProtocolError(String message) {
        super(message);
    }

    public CTAPProtocolError(String message, Throwable throwable) {
        super(message, throwable);
    }
}
