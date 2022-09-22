package pro.javacard.fido2.cli;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.*;
import java.io.IOException;

public class CLICallbacks implements CallbackHandler {
    private static final Logger logger = LoggerFactory.getLogger(CLICallbacks.class);

    private static final String ENV_FIDO_PIN = "FIDO_PIN";

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (callbacks.length != 1)
            throw new IOException("Only one callback allowed");
        if (callbacks[0] instanceof PasswordCallback) {
            PasswordCallback pwc = (PasswordCallback) callbacks[0];
            if (System.getenv().containsKey(ENV_FIDO_PIN)) {
                logger.warn("Using ${} for PIN", ENV_FIDO_PIN);
                String p = System.getenv(ENV_FIDO_PIN);
                pwc.setPassword(p.toCharArray());
            } else
                pwc.setPassword(System.console().readPassword(pwc.getPrompt() + ": "));
        } else if (callbacks[0] instanceof TextOutputCallback) {
            TextOutputCallback pwc = (TextOutputCallback) callbacks[0];
            System.out.printf("%s%n", pwc.getMessage());
        } else throw new UnsupportedCallbackException(callbacks[0]);
    }

    public static boolean hasPIN() {
        return System.getenv().containsKey(ENV_FIDO_PIN);
    }

}
