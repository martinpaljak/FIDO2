package pro.javacard.fido2.common.mds;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class MetaDataService {

    static ObjectMapper mapper = new ObjectMapper();
    ObjectNode jwt;

    MetaDataService(ObjectNode blob) {
        //jwt = mapper.readTree(blob);
    }

    public static void main(String[] args) throws Exception {
        try (InputStream blob = MetaDataService.class.getResourceAsStream("blob.jwt")) {
            if (blob == null) {
                throw new IllegalArgumentException("Blob is null");
            }
            String jwt = new String(blob.readAllBytes(), StandardCharsets.US_ASCII);
            String[] elements = jwt.split("\\.");
            ObjectNode header = (ObjectNode) mapper.readTree(Base64.getUrlDecoder().decode(elements[0]));
            ObjectNode payload = (ObjectNode) mapper.readTree(Base64.getUrlDecoder().decode(elements[1]));
            byte[] signature = Base64.getUrlDecoder().decode(elements[2]);

            System.out.println(header);
            System.out.println(Hex.toHexString(signature));

            payload.fieldNames().forEachRemaining(System.out::println);
            System.out.println("MDS #" + payload.get("no").asInt());

            HashMap<String, Set<String>> countries = new HashMap<>();

            for (JsonNode n : payload.get("entries")) {
                String device = n.get("metadataStatement").get("description").asText();
                System.out.println("Device: " + device);
                //n.fieldNames().forEachRemaining(System.out::println);
                if (device.equals("Touch ID, Face ID, or Passcode"))
                    System.out.println(n.get("metadataStatement").toPrettyString());
                System.out.println(n.get("metadataStatement").get("attestationTypes").toPrettyString());
                if (n.get("metadataStatement").has("attestationCertificateKeyIdentifiers"))
                    System.out.println("Keys: " + n.get("metadataStatement").get("attestationCertificateKeyIdentifiers").toPrettyString());
                if (n.get("metadataStatement").has("attestationRootCertificates")) {
                    for (JsonNode c : n.get("metadataStatement").get("attestationRootCertificates")) {
                        X509CertificateHolder holder = new X509CertificateHolder(Base64.getDecoder().decode(c.asText()));
                        SubjectKeyIdentifier ident = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(holder.getSubjectPublicKeyInfo());
                        String id = Hex.toHexString(ident.getKeyIdentifier());

                        final String cn;
                        if (holder.getSubject().getRDNs(BCStyle.C).length > 0) {
                            cn = holder.getSubject().getRDNs(BCStyle.C)[0].getFirst().getValue().toString();

                        } else if (id.equals("4915642dd5bbc6de333a5e0995fc872336d3bf0b")) {
                            cn = "CN";
                        } else if (id.equals("2022fcf46cd1898638294e892cc8aa4ff71bfda0")) {
                            cn = "SE";
                        } else {
                            System.err.println("Error: no C for " + device + ": " + holder.getSubject() + " " + id);
                            continue;
                        }
                        System.out.println("ID: " + id + " " + cn);
                        if (!countries.containsKey(cn)) {
                            countries.put(cn, new HashSet<>(Collections.singleton(device)));
                        } else {
                            countries.get(cn).add(device);
                        }

                    }
                    //System.out.println(n.get("metadataStatement").get("attestationRootCertificates").toPrettyString());
                }
                //break;
            }

            for (Map.Entry<String, Set<String>> country : countries.entrySet()) {
                System.out.println(country.getKey() + ": " + country.getValue().size());
            }
        }
    }
}
