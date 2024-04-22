package ee.ria.eudi.qeaa.as.service;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.model.AuthorizationServerMetadata;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.List;

import static ee.ria.eudi.qeaa.as.controller.AuthorizationController.AUTHORIZE_REQUEST_MAPPING;
import static ee.ria.eudi.qeaa.as.controller.MetadataController.WELL_KNOWN_JWKS_REQUEST_MAPPING;
import static ee.ria.eudi.qeaa.as.controller.ParController.PAR_REQUEST_MAPPING;
import static ee.ria.eudi.qeaa.as.controller.TokenController.TOKEN_REQUEST_MAPPING;

@Service
@RequiredArgsConstructor
public class MetadataService {
    private final AuthorizationServerProperties authorizationServerProperties;
    private final ECKey asSigningKey;

    @Cacheable("metadata")
    public AuthorizationServerMetadata getMetadata() {
        String baseUrl = authorizationServerProperties.as().baseUrl();
        return AuthorizationServerMetadata.builder()
            .issuer(baseUrl)
            .authorizationEndpoint(baseUrl + AUTHORIZE_REQUEST_MAPPING)
            .tokenEndpoint(baseUrl + TOKEN_REQUEST_MAPPING)
            .pushedAuthorizationRequestEndpoint(baseUrl + PAR_REQUEST_MAPPING)
            .requirePushedAuthorizationRequests(true)
            .jwksUri(baseUrl + WELL_KNOWN_JWKS_REQUEST_MAPPING)
            .grantTypesSupported(List.of("authorization_code"))
            .responseTypesSupported(List.of("code"))
            .tokenEndpointAuthMethodsSupported(List.of("attest_jwt_client_auth"))
            .dpopSigningAlgValuesSupported(List.of(
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "PS384",
                "PS256",
                "PS512"
            ))
            .requestObjectSigningAlgValuesSupported(List.of(
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "PS384",
                "PS256",
                "PS512"
            ))
            .codeChallengeMethodsSupported(List.of("S256"))
            .build();
    }

    @Cacheable("jwk_set")
    public JWKSet getJwkSet() {
        return new JWKSet(asSigningKey.toPublicJWK());
    }
}
