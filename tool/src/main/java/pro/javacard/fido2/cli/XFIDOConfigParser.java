package pro.javacard.fido2.cli;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.fasterxml.jackson.dataformat.javaprop.JavaPropsFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class XFIDOConfigParser {

    private static final ObjectMapper json;
    private static final ObjectMapper yaml;
    private static final ObjectMapper props;
    private static final ObjectMapper cbor;
    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        // When using strings for binary
        SimpleModule hexModule = new SimpleModule();
        hexModule.addSerializer(byte[].class, new BytesAsHexSerializer());
        hexModule.addDeserializer(byte[].class, new BytesAsHexDeserializer());

        json = new ObjectMapper();
        json.registerModule(hexModule);
        json.enable(JsonReadFeature.ALLOW_UNQUOTED_FIELD_NAMES.mappedFeature());
        json.enable(JsonReadFeature.ALLOW_JAVA_COMMENTS.mappedFeature());
        json.enable(JsonReadFeature.ALLOW_YAML_COMMENTS.mappedFeature());
        json.enable(JsonReadFeature.ALLOW_SINGLE_QUOTES.mappedFeature());


        props = new ObjectMapper(new JavaPropsFactory());
        props.registerModule(hexModule);

        YAMLFactory factory = new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER).enable(YAMLGenerator.Feature.MINIMIZE_QUOTES);
        yaml = new ObjectMapper(factory);
        yaml.registerModule(hexModule);

        // TODO: Add CBOR.compact(byte[]) => byte[] to get rid of break codes and cast back to fixed length arrays/maps
        cbor = new CBORMapper();
    }

    public static JsonNode parsePathOrString(String s) {
        try {
            Path path = Paths.get(s);

            if (Files.exists(path)) {
                String payload = Files.readString(path).trim();
                if (s.endsWith(".yaml") || s.endsWith(".yml")) {
                    return mapper.valueToTree(yaml.readValue(payload, XFIDOConfig.class));
                } else if (s.endsWith(".json") || payload.startsWith("{")) {
                    return mapper.valueToTree(json.readValue(payload, XFIDOConfig.class));
                } else if (s.endsWith(".properties") || (payload.contains(".") && payload.contains("="))) {
                    return mapper.valueToTree(props.readValue(payload, XFIDOConfig.class));
                }
            } else {
                return parseString(s);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        throw new IllegalArgumentException("Unrecognized content for " + s);
    }

    public static JsonNode parseString(String s) throws IOException {
        s = s.trim();
        if (s.startsWith("{")) {
            return mapper.valueToTree(json.readValue(s, XFIDOConfig.class));
        } else if (s.contains(".") && s.contains("=")) {
            return mapper.valueToTree(props.readValue(s, XFIDOConfig.class));
        } else
            return JsonNodeFactory.instance.textNode(s);
    }

    static public class BytesAsHexDeserializer extends JsonDeserializer<byte[]> {
        @Override
        public byte[] deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
            return Hex.decode(jsonParser.getValueAsString());
        }
    }

    static public class BytesAsHexSerializer extends JsonSerializer<byte[]> {

        @Override
        public void serialize(byte[] bytes, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            jsonGenerator.writeString(Hex.toHexString(bytes));
        }
    }
}
