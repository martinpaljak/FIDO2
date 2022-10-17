package pro.javacard.fido2.common;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

public class AttestationVerifier {
    private static final Logger logger = LoggerFactory.getLogger(AttestationVerifier.class);

    static boolean valid(byte[] signature, byte[] dtbs, X509Certificate signer) throws GeneralSecurityException {
        return valid(signature, dtbs, signer.getPublicKey());
    }

    static boolean valid(byte[] signature, byte[] dtbs, PublicKey signer) throws GeneralSecurityException {
        logger.debug("Signature: {}", Hex.toHexString(signature));
        Signature ecdsa_p256 = Signature.getInstance("SHA256withECDSA");
        ecdsa_p256.initVerify(signer);
        ecdsa_p256.update(dtbs);
        if (!ecdsa_p256.verify(signature)) {
            throw new GeneralSecurityException("Attestation verification failed");
        }
        logger.info("Attestation signature verified");
        return true;
    }

    public static void dumpAttestation(MakeCredentialCommand command, ObjectNode registration) {
        try {
            if (registration.get("fmt").asText().equals("fido-u2f")) {
                byte[] x509 = registration.get("attStmt").get("x5c").get(0).binaryValue();
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(x509));
                logger.info("Attestation: " + cert.getSubjectX500Principal() + " by " + cert.getIssuerX500Principal());
                byte[] signature = registration.get("attStmt").get("sig").binaryValue();
                byte[] dtbs = attestation_dtbs(command, registration);
                valid(signature, dtbs, cert);
            } else if (registration.get("fmt").asText().equals("packed")) {
                if (registration.get("attStmt").has("x5c")) {
                    byte[] x509 = registration.get("attStmt").get("x5c").get(0).binaryValue();
                    CertificateFactory cf = CertificateFactory.getInstance("X509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(x509));
                    logger.info("Attestation: " + cert.getSubjectX500Principal() + " by " + cert.getIssuerX500Principal());
                    byte[] signature = registration.get("attStmt").get("sig").binaryValue();
                    byte[] dtbs = attestation_dtbs(command, registration);
                    valid(signature, dtbs, cert);
                } else {
                    logger.info("self-attestation");
                    byte[] signature = registration.get("attStmt").get("sig").binaryValue();
                    byte[] dtbs = attestation_dtbs(command, registration);
                    AuthenticatorData authenticatorData = AuthenticatorData.fromBytes(registration.get("authData").binaryValue());
                    valid(signature, dtbs, authenticatorData.getAttestation().getPublicKey());
                }
            }
        } catch (IOException | GeneralSecurityException e) {
            logger.error("Failed to parse/verify attestation: " + e.getMessage(), e);
        }
    }


    static byte[] attestation_dtbs(MakeCredentialCommand command, ObjectNode registration) {
        try {
            if (registration.get("fmt").asText().equals("fido-u2f")) {
                AuthenticatorData authenticatorData = AuthenticatorData.fromBytes(registration.get("authData").binaryValue());
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                bos.write(0x00); // fixed
                bos.write(authenticatorData.rpIdHash);
                bos.write(command.clientDataHash);
                bos.write(authenticatorData.getAttestation().getCredentialID());
                bos.write(P256.pubkey2uncompressed((ECPublicKey) authenticatorData.getAttestation().getPublicKey()));
                return bos.toByteArray();
            } else if (registration.get("fmt").asText().equals("packed")) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                bos.write(registration.get("authData").binaryValue());
                bos.write(command.clientDataHash);
                return bos.toByteArray();
            } else {
                throw new IllegalStateException("Unsupported attestation format: " + registration.get("fmt").asText());
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
