package pro.javacard.fido2.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;

public class AssertionVerifier {
    private static final Logger logger = LoggerFactory.getLogger(AssertionVerifier.class);

    public static boolean verify(AuthenticatorData authenticatorData, byte[] clientDataHash, byte[] signature, PublicKey publicKey) {
        try {
            final Signature verifier;
            if (publicKey instanceof EdECPublicKey) {
                verifier = Signature.getInstance("Ed25519");
            } else {
                verifier = Signature.getInstance("SHA256withECDSA");
            }
            // Verify assertion, if pubkey given
            verifier.initVerify(publicKey);
            verifier.update(authenticatorData.getBytes());
            verifier.update(clientDataHash);
            if (verifier.verify(signature)) {
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
