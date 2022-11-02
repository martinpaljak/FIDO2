package pro.javacard.fido2.cli;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

// X-FIDO config for getting right types when using property format (x.y=z) from command line and
// for parsing hex for byte arrays.
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class XFIDOConfig {

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public final static class Credential {
        @JsonProperty(required = true)
        public byte[] id;
        @JsonProperty(required = true)
        public String origin;
        @JsonProperty(required = true)
        public byte[] uid;
        @JsonProperty(required = true)
        public byte[] pubkey;
        public byte[] private_key;
        public Integer protection;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public final static class Rule {
        @JsonProperty(required = true)
        public String pattern;
        public Boolean allow;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public final static class Authority {
        public String origin;
        public byte[] pubkey;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public final static class NFC {
        public String url;
        public Boolean enabled;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public final static class PIN {
        public Boolean enabled;
        public Boolean managed;
        public Boolean change;
        public String value;
        public PinPolicy policy;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class Config {
        public Integer rules;
        public Integer credentials;
        public byte[] pubkey;
        public byte[] att_key;
        public byte[] att_cert;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public final static class PinPolicy {
        public Integer min;
        public Integer max;
        public Boolean allow_upped;
        public Boolean allow_lower;
        public Boolean allow_number;
        public Boolean allow_special;

        public Boolean require_upper;
        public Boolean require_lower;
        public Boolean require_number;
        public Boolean require_special;
    }

    public Config config;
    public PIN pin;
    public Authority authority;
    public List<Credential> credentials;
    public List<Rule> rules;
    public NFC nfc;
}
