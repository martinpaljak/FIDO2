package pro.javacard.fido2.common;

public class CTAPProtocolError extends RuntimeException {

    private static final long serialVersionUID = 6495521863179051131L;
    public CTAPProtocolError(String message) {
        super(message);
    }

    public CTAPProtocolError(String message, Throwable throwable) {
        super(message, throwable);
    }
}
