package pro.javacard.fido2.common;

import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class AttestationCATests {


    @Test
    public void makeKey() {
        KeyPair keyPair = P256.ephemeral();

        System.out.println(Hex.toHexString(((ECPrivateKey) keyPair.getPrivate()).getS().toByteArray()));
        System.out.println(Hex.toHexString(((ECPublicKey) keyPair.getPublic()).getW().getAffineX().toByteArray()));
        System.out.println(Hex.toHexString(((ECPublicKey) keyPair.getPublic()).getW().getAffineY().toByteArray()));
    }

    @Test
    public void makeCert() throws Exception {
        AttestationCA ca = new AttestationCA();
        X509Certificate rootCert = ca.makeRootCertificate();
        System.out.println(Hex.toHexString(rootCert.getEncoded()));
        byte[] AAGUID = new byte[]{(byte) 0xac, (byte) 0x5e, (byte) 0xbf, (byte) 0x97, (byte) 0x14, (byte) 0x9e, 0x4b, 0x1c, (byte) 0x97, 0x73, 0x00, (byte) 0xdb, 0x72, (byte) 0xd3, (byte) 0x99, (byte) 0xe2};


        KeyPair keyPair = P256.ephemeral();
        System.out.println("Attestation key: " + Hex.toHexString(((ECPrivateKey) keyPair.getPrivate()).getS().toByteArray()));
        System.out.println("Attestation cert: " + Hex.toHexString(ca.makeAttestationCertificate((ECPublicKey) keyPair.getPublic(), AAGUID).getEncoded()));
    }
}
