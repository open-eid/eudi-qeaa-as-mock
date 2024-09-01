package ee.ria.eudi.qeaa.as.controller;

import ee.ria.eudi.qeaa.as.service.AuthorizationServerMetadata;
import ee.ria.eudi.qeaa.as.service.MetadataService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class MetadataController {
    public static final String WELL_KNOWN_OPENID_CONFIGURATION_REQUEST_MAPPING = "/.well-known/openid-configuration";
    public static final String WELL_KNOWN_OAUTH_CONFIGURATION_REQUEST_MAPPING = "/.well-known/oauth-authorization-server";
    public static final String WELL_KNOWN_JWKS_REQUEST_MAPPING = "/.well-known/jwks.json";
    private final MetadataService metadataService;

    @GetMapping(path = {WELL_KNOWN_OAUTH_CONFIGURATION_REQUEST_MAPPING, WELL_KNOWN_OPENID_CONFIGURATION_REQUEST_MAPPING}, produces = MediaType.APPLICATION_JSON_VALUE)
    public AuthorizationServerMetadata getMetadata() {
        return metadataService.getMetadata();
    }

    @GetMapping(path = WELL_KNOWN_JWKS_REQUEST_MAPPING, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getJwkSet() {
        return metadataService.getJwkSet().toPublicJWKSet().toJSONObject();
    }
}
