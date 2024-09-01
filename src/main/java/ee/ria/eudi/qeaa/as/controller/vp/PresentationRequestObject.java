package ee.ria.eudi.qeaa.as.controller.vp;

import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;
import lombok.RequiredArgsConstructor;

@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record PresentationRequestObject(
    String clientId,
    ClientIdScheme clientIdScheme,
    ResponseType responseType,
    ResponseMode responseMode,
    String responseUri,
    VerifierMetadata clientMetadata,
    PresentationDefinition presentationDefinition,
    String nonce,
    String state) {

    public enum ClientIdScheme {
        X509_SAN_DNS, VERIFIER_ATTESTATION;

        @JsonValue
        public String value() {
            return this.name().toLowerCase();
        }
    }

    @RequiredArgsConstructor
    public enum ResponseType {
        VP_TOKEN("vp_token"), VP_TOKEN_ID_TOKEN("vp_token id_token"), CODE("code");
        private final String value;

        @JsonValue
        public String value() {
            return value;
        }
    }

    public enum ResponseMode {
        DIRECT_POST, FRAGMENT;

        @JsonValue
        public String value() {
            return this.name().toLowerCase();
        }
    }
}
