package ee.ria.eudi.qeaa.as.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;

import java.util.List;

@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthorizationServerMetadata(
    String issuer,
    String authorizationEndpoint,
    String tokenEndpoint,
    String pushedAuthorizationRequestEndpoint,
    boolean requirePushedAuthorizationRequests,
    String jwksUri,
    List<String> grantTypesSupported,
    List<String> responseTypesSupported,
    List<String> tokenEndpointAuthMethodsSupported,
    List<String> dpopSigningAlgValuesSupported,
    List<String> requestObjectSigningAlgValuesSupported,
    List<String> codeChallengeMethodsSupported) {
}
