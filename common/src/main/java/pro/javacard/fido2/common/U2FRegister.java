package pro.javacard.fido2.common;

import apdu4j.core.CommandAPDU;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class U2FRegister {
    private static final Logger logger = LoggerFactory.getLogger(U2FRegister.class);


    void verifyU2FRegistration(MakeCredentialCommand command) throws IllegalArgumentException {
        if (command.options.getOrDefault("rk", false))
            throw new IllegalArgumentException("rk is not supported");
        if (command.options.getOrDefault("uv", false))
            throw new IllegalArgumentException("uv is not supported");
        if (command.extensions.size() > 0)
            throw new IllegalArgumentException("extensions are not supported");
        if (command.algorithms.size() != 1 || command.algorithms.get(0) != COSEPublicKey.P256)
            throw new IllegalArgumentException("U2F supports only P256");
    }

    @SuppressWarnings("deprecation")
    public static byte[] toCBOR(MakeCredentialCommand command, byte[] response) throws IOException {

        int offset = 0;
        if (response[offset++] != 0x05)
            throw new IllegalArgumentException("response[0] is not 0x05");
        // pubkey
        byte[] pubkey = Arrays.copyOfRange(response, offset, offset + 65);
        offset += 65;
        logger.debug("Pubkey: {}", Hex.toHexString(pubkey));

        // Keyhandle
        int keyhandlelen = response[offset++] & 0xFF;
        byte[] keyhandle = Arrays.copyOfRange(response, offset, offset + keyhandlelen);
        offset += keyhandlelen;
        logger.debug("keyhandle: {}", Hex.toHexString(keyhandle));

        // Attestation certificate and signature
        byte[] x509 = Arrays.copyOfRange(response, offset, response.length);
        //logger.debug("certificate: {}", Hex.toHexString(x509));

        final byte[] cert;
        try (ASN1InputStream inp = new ASN1InputStream(x509)) {
            cert = new X509CertificateHolder(Certificate.getInstance(inp.readObject())).getEncoded();
            offset += cert.length;
        }

        byte[] signature = Arrays.copyOfRange(response, offset, response.length);

        ByteArrayOutputStream attestedCredData = new ByteArrayOutputStream();
        attestedCredData.write(new byte[16]); // AAGUID

        attestedCredData.write(0); // XXX key handle length on TWO bytes unlikely
        attestedCredData.write(keyhandlelen);

        attestedCredData.write(keyhandle);

        attestedCredData.write(P256.pubkey2cbor(P256.uncompressed2pubkey(pubkey)));

        logger.debug("Attestation data: " + Hex.toHexString(attestedCredData.toByteArray()));

        ByteArrayOutputStream authenticatorData = new ByteArrayOutputStream();
        authenticatorData.write(PINProtocols.sha256(command.origin.getBytes(StandardCharsets.UTF_8)));
        authenticatorData.write(0x41); // AT + UP
        authenticatorData.write(new byte[4]); // counter: zero
        authenticatorData.write(attestedCredData.toByteArray()); // attestation data


        logger.debug("Authenticator data: " + Hex.toHexString(authenticatorData.toByteArray()));

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        CBORGenerator generator = new CBORFactory().createGenerator(result);
        generator.writeStartObject(3);

        generator.writeFieldId(1);
        generator.writeString("fido-u2f");

        generator.writeFieldId(2);
        generator.writeBinary(authenticatorData.toByteArray());

        generator.writeFieldId(3);
        generator.writeStartObject(2);
        generator.writeFieldName("sig");
        generator.writeBinary(signature);
        generator.writeFieldName("x5c");
        generator.writeStartArray(1);
        generator.writeBinary(cert);
        generator.writeEndArray();
        generator.writeEndObject(); // sig+x509 dict

        generator.writeEndObject(); // attestation
        generator.close();

        return result.toByteArray();
    }

    public static byte[] toRegisterCommand(MakeCredentialCommand command) {
        byte[] appid = PINProtocols.sha256(command.origin.getBytes(StandardCharsets.UTF_8));
        logger.debug("AppID: {}", Hex.toHexString(appid));

        // Do mapping
        byte[] payload = CryptoUtils.concatenate(command.clientDataHash, appid);
        // Needs to be extended length, thus 65536
        return new CommandAPDU(0x00, 0x01, 0x00, 0x00, payload, 65536).getBytes();
    }
}
