package pro.javacard.fido2.common;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Date;

// This is a sample Attestation certificate CA
public class AttestationCA {
    private static final Logger logger = LoggerFactory.getLogger(AttestationCA.class);

    static final byte[] rootPrivate = Hex.decode("314daf146b500e808360c0c904826c7afd259f401776a0dc7e6be14ce306ba49");
    static final byte[] rootPublic = Hex.decode("043e7cf2b8b3685363d6d44ad417071398140547f9fc9cf058e6b834c30c36c02a0fc51e8c438e339dede6e69013eab8f851d2edee8786653fdbc6ac9b60a00fca");

    public static final byte[] rootCertificate = Hex.decode("308201793082011fa003020102020401346607300a06082a8648ce3d04030230323130302e06035504030c276a617661636172642e70726f206174746573746174696f6e20726f6f7420233230323131323037301e170d3231303130313030303030305a170d3435303130313030303030305a30323130302e06035504030c276a617661636172642e70726f206174746573746174696f6e20726f6f74202332303231313230373059301306072a8648ce3d020106082a8648ce3d030107034200043e7cf2b8b3685363d6d44ad417071398140547f9fc9cf058e6b834c30c36c02a0fc51e8c438e339dede6e69013eab8f851d2edee8786653fdbc6ac9b60a00fcaa323302130120603551d130101ff040830060101ff020100300b0603551d0f040403020284300a06082a8648ce3d04030203480030450220509d5b1b0d66b3efd632004580965283b800a3b8e1d6ea25ad5ff94ea1d73089022100e941ecb919316ce1b03ecfa81ad293a8f053cd2446b00d1ba146c4e082e7e3ef");

    public static final byte[] attestationPrivate = Hex.decode("fa18ca8b592245111416bf023ab28e06d1ea829d276365e2d0e05509d0b04674");
    public static final byte[] attestationCertificate = Hex.decode("308201b230820159a003020102020101300a06082a8648ce3d04030230323130302e06035504030c276a617661636172642e70726f206174746573746174696f6e20726f6f7420233230323131323037301e170d3231303130313030303030305a170d3435303130313030303030305a304a310b300906035504061302454531173015060355040a0c0e4fc39c204bc3bc62657270756e6b31223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e3059301306072a8648ce3d020106082a8648ce3d030107034200044c129336dd4989ef135450fec63e20136530e508744500a474dc3a72d6487b01e7e0f96219b675217e7b34c58b522844de3bacac8effcb9b1291a2a740887cc1a3483046300c0603551d130101ff040230003013060b2b0601040182e51c0201010404030204103021060b2b0601040182e51c0101040412041000000000000000000000000000000000300a06082a8648ce3d040302034700304402202b5bed230f194148ed0d439fffeb1a8b2fe95cfbfd032e1af384d7cd0dcc40c602206ea8e226fe7ff0d9a6877240af31c5050b032fc25277cc1cc81162fa4b8cae0a");

    // See https://www.w3.org/TR/webauthn/#sctn-packed-attestation-cert-requirements
    // And https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#attestation-statement-certificate-requirements
    BigInteger rootSerial = BigInteger.valueOf(20220927);

    final X500Name rootSubject = new X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, "javacard.pro test attestation root #" + rootSerial)
            .build();

    final X500Name attestationSubject = new X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.C, "EE")
            .addRDN(BCStyle.O, "OÜ Küberpunk")
            .addRDN(BCStyle.OU, "Authenticator Attestation") // NB! This is important
            .build();


    X509Certificate makeRootCertificate() throws Exception {
        ECPrivateKey privateKey = CryptoUtils.private2privkey(rootPrivate);
        ECPublicKey publicKey = CryptoUtils.uncompressed2pubkey(rootPublic);

        // start data
        Date startDate = Date.from(LocalDate.of(2022, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());
        Date endDate = Date.from(LocalDate.of(2045, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());

        // Basic certificate
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(rootSubject, rootSerial, startDate, endDate, rootSubject, publicKey);

        // Extensions. CA true, len = 0
        BasicConstraints basicConstraints = new BasicConstraints(0); // True, length == 0
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);// Critical

        // Extension: usage cert signing
        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature);
        certBuilder.addExtension(Extension.keyUsage, false, usage.getEncoded());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(privateKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));
    }


    X509Certificate makeAttestationCertificate(ECPublicKey attestationPublicKey, byte[] aaguid) throws Exception {
        ECPrivateKey privateKey = CryptoUtils.private2privkey(rootPrivate);

        // Serial == 1
        BigInteger certSerialNumber = BigInteger.ONE;

        Date startDate = Date.from(LocalDate.of(2022, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());
        Date endDate = Date.from(LocalDate.of(2045, 1, 1).atStartOfDay(ZoneOffset.UTC).toInstant());

        // Basic certificate
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(rootSubject, certSerialNumber, startDate, endDate, attestationSubject, attestationPublicKey);

        // Extensions - MUST CA FALSE
        BasicConstraints basicConstraints = new BasicConstraints(false);
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

        // Extension: transports 1.3.6.1.4.1.45724.2.1.1 NFC = 3 MUST be wrapped in octet string (ref: ?)
        certBuilder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.2.1.1"), false, new DEROctetString(new DERBitString(0x10)));

        // Extension: AAGUID
        certBuilder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"), false, new DEROctetString(aaguid));

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(privateKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));
    }

    //@Test
    public void makeKey() {
        KeyPair keyPair = CryptoUtils.ephemeral();

        System.out.println(Hex.toHexString(((ECPrivateKey) keyPair.getPrivate()).getS().toByteArray()));
        System.out.println(Hex.toHexString(((ECPublicKey) keyPair.getPublic()).getW().getAffineX().toByteArray()));
        System.out.println(Hex.toHexString(((ECPublicKey) keyPair.getPublic()).getW().getAffineY().toByteArray()));
    }

    //@Test
    public void makeCert() throws Exception {
        X509Certificate rootCert = makeRootCertificate();
        System.out.println(Hex.toHexString(rootCert.getEncoded()));

        KeyPair keyPair = CryptoUtils.ephemeral();
        System.out.println("Attestation key: " + Hex.toHexString(((ECPrivateKey) keyPair.getPrivate()).getS().toByteArray()));
        System.out.println("Attestation cert: " + Hex.toHexString(makeAttestationCertificate((ECPublicKey) keyPair.getPublic(), new byte[16]).getEncoded()));
    }
}
