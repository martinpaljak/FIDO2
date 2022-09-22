package pro.javacard.fido2.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

public class AssertionVerifier {
    private static final Logger logger = LoggerFactory.getLogger(AssertionVerifier.class);

    public static boolean verify(AuthenticatorData authenticatorData, byte[] clientDataHash, byte[] signature, ECPublicKey publicKey) {
        try {
            // Verify assertion, if pubkey given
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initVerify(publicKey);
            ecdsa.update(authenticatorData.getBytes());
            ecdsa.update(clientDataHash);
            if (ecdsa.verify(signature)) {
                logger.info("Verified OK.");
                return true;
            } else {
                logger.warn("Not verified!");
                return false;
            }
        } catch (GeneralSecurityException e) {
            logger.error("Failed to verify assertion: " + e.getMessage(), e);
            return false;
        }
    }
}
