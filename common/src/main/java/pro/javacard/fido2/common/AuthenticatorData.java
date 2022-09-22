package pro.javacard.fido2.common;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.EnumSet;
import java.util.stream.Collectors;

public class AuthenticatorData {
    public enum Flag {
        UP(0x01), UV(0x02), AT(0x40), ED(0x80);
        final byte mask;

        Flag(int mask) {
            this.mask = (byte) (mask & 0xFF);
        }

        static EnumSet<Flag> fromByte(byte b) {
            EnumSet<Flag> r = EnumSet.noneOf(Flag.class);
            for (Flag f : values()) {
                if ((b & f.mask) == f.mask)
                    r.add(f);
            }
            return r;
        }
    }

    final byte[] authData;
    final byte[] rpIdHash;
    final EnumSet<Flag> flags;
    final long counter;
    final AttestationData attestation;
    final ObjectNode extensions;


    private AuthenticatorData(byte[] authData, byte[] rpIdHash, EnumSet<Flag> flags, long counter, AttestationData attestation, ObjectNode extensions) {
        this.authData = authData.clone();
        this.rpIdHash = rpIdHash.clone();
        this.flags = EnumSet.copyOf(flags);
        this.counter = counter;
        if (flags.contains(Flag.AT) && attestation == null) {
            throw new IllegalArgumentException("Attestation flag set but no attestation data!");
        } else if (!flags.contains(Flag.AT) && attestation != null) {
            throw new IllegalArgumentException("Attestation flag no set but attestation data set!");
        } else
            this.attestation = attestation;
        if (flags.contains(Flag.ED) && extensions == null) {
            throw new IllegalArgumentException("Extensions flag set but extensions data!");
        } else if (!flags.contains(Flag.ED) && extensions != null) {
            throw new IllegalArgumentException("No extensions flag but extensions data set!");
        } else
            this.extensions = extensions;
    }

    public static AuthenticatorData fromBytes(byte[] bytes) throws IOException {
        ByteBuffer b = ByteBuffer.wrap(bytes);
        byte[] rpIdHash = new byte[32];
        b.get(rpIdHash);
        byte _flags = b.get();
        EnumSet<Flag> flags = Flag.fromByte(_flags);
        long counter = Integer.toUnsignedLong(b.getInt());
        int optionalPosition = 32 + 1 + 4;
        AttestationData attestationData = null;
        ObjectNode extensions = null;
        // if AT, read attestation
        if (b.hasRemaining() && flags.contains(Flag.AT)) {
            byte[] attestationAndExtensions = new byte[b.remaining()];
            b.get(attestationAndExtensions);
            attestationData = AttestationData.fromBytes(attestationAndExtensions);
        }
        // Rewind to optional position
        b.position(optionalPosition);
        // if ED, read extensions
        if (b.hasRemaining() && flags.contains(Flag.ED)) {
            // Skip AT if present
            if (flags.contains(Flag.AT) && attestationData != null)
                b.position(b.position() + attestationData.getLength());
            byte[] exts = new byte[b.remaining()];
            b.get(exts);
            //System.out.println("Extensions data: " + Hex.toHexString(exts));
            extensions = (ObjectNode) CTAP2ProtocolHelpers.cborMapper.readTree(exts);
        }
        return new AuthenticatorData(bytes, rpIdHash, flags, counter, attestationData, extensions);
    }

    public byte[] getRpIdHash() {
        return rpIdHash.clone();
    }

    public long getCounter() {
        return counter;
    }

    public AttestationData getAttestation() {
        return attestation;
    }

    @Override
    public String toString() {
        return "AuthenticatorData{" +
                "rpIdHash=" + Hex.toHexString(getRpIdHash()) +
                ", flags=" + flags +
                ", counter=" + counter +
                ", attestation=" + attestation +
                ", extensions=" + extensions +
                '}';
    }

    public ObjectNode toJSON() {
        ObjectNode response = JsonNodeFactory.instance.objectNode();
        response.put("rpIdHash", Hex.toHexString(rpIdHash));
        ArrayNode fs = JsonNodeFactory.instance.arrayNode();
        fs.addAll(flags.stream().map(Flag::name).map(TextNode::new).collect(Collectors.toList()));
        response.set("flags", fs);
        response.put("counter", counter);
        if (flags.contains(Flag.AT))
            response.set("attestation", attestation.toJSON());
        if (flags.contains(Flag.ED))
            response.set("extensions", extensions);
        return response;
    }

    public byte[] getBytes() {
        return authData.clone();
    }
}
