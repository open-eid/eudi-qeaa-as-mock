package ee.ria.eudi.qeaa.as.controller.vp;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;

import java.util.List;
import java.util.Map;

@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record VerifierMetadata(
    String clientName,
    String clientUri,
    String logoUri,
    String authorizationEncryptedResponseAlg,
    String authorizationEncryptedResponseEnc,
    Map<String, Object> jwks,
    VpFormats vpFormats) {

    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record VpFormats(MsoMdoc msoMdoc) {
    }

    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record MsoMdoc(List<String> alg) {
    }
}
