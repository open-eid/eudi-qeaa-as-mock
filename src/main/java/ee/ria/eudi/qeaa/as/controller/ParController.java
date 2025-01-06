package ee.ria.eudi.qeaa.as.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.State;
import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.model.Session;
import ee.ria.eudi.qeaa.as.repository.SessionRepository;
import ee.ria.eudi.qeaa.as.validation.AuthorizationRequestValidator;
import ee.ria.eudi.qeaa.as.validation.ClientAttestationValidator;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;

@RestController
@RequiredArgsConstructor
public class ParController {
    public static final String PAR_REQUEST_MAPPING = "/as/par";
    public static final String REQUIRED_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation";
    public static final String REQUIRED_CLIENT_ASSERTION_FORMAT = "[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+~[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+";
    private static final String REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";
    private final AuthorizationServerProperties.AuthorizationServer asProperties;
    private final ClientAttestationValidator clientAttestationValidator;
    private final AuthorizationRequestValidator authorizationRequestValidator;
    private final SessionRepository sessionRepository;
    private final ObjectMapper objectMapper;

    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126.html">OAuth 2.0 Pushed Authorization Requests</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9101">JWT-Secured Authorization Request (JAR)</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-02">OAuth 2.0 Attestation-Based Client Authentication</a>
     */
    @PostMapping(path = PAR_REQUEST_MAPPING, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE, params = "!authorization_details")
    public ResponseEntity<ParResponse> par(@RequestParam(name = "request") String request,
                                           @RequestParam(name = "client_assertion_type") @Pattern(regexp = REQUIRED_CLIENT_ASSERTION_TYPE) String clientAssertionType,
                                           @RequestParam(name = "client_assertion") @Pattern(regexp = REQUIRED_CLIENT_ASSERTION_FORMAT) String clientAssertion) throws ParseException {
        String audience = asProperties.baseUrl() + PAR_REQUEST_MAPPING;
        Pair<SignedJWT, SignedJWT> clientAttestationAndPoP = clientAttestationValidator.validate(clientAssertion, audience);
        JWTClaimsSet requestObjectClaimsSet = authorizationRequestValidator.validate(request, clientAttestationAndPoP.getLeft());

        URI requestUri = URI.create(REQUEST_URI_PREFIX + new State().getValue());
        createSession(requestUri, requestObjectClaimsSet);
        long expiresIn = asProperties.ttl().requestUri().toSeconds();
        return ResponseEntity.status(HttpStatus.CREATED).body(new ParResponse(requestUri, expiresIn));
    }

    @PostMapping(path = PAR_REQUEST_MAPPING, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE, params = "!request")
    public ResponseEntity<ParResponse> par(@RequestParam(name = "authorization_details") String authorizationDetails,
                                           @RequestParam(name = "client_id") String clientId,
                                           @RequestParam(name = "state") String state,
                                           @RequestParam(name = "response_type") String responseType,
                                           @RequestParam(name = "code_challenge") String codeChallenge,
                                           @RequestParam(name = "code_challenge_method") String codeChallengeMethod,
                                           @RequestParam(name = "prompt", required = false) String prompt,
                                           @RequestParam(name = "redirect_uri") String redirectUri) throws ParseException, JsonProcessingException {

        List<Object> authDetails = objectMapper.readValue(authorizationDetails, new TypeReference<>() {
        });
        JWTClaimsSet authorizationRequestClaims = new JWTClaimsSet.Builder()
            .issuer(clientId)
            .audience(asProperties.baseUrl() + PAR_REQUEST_MAPPING)
            .claim("authorization_details", authDetails)
            .claim("client_id", clientId)
            .claim("state", state)
            .claim("response_type", responseType)
            .claim("code_challenge", codeChallenge)
            .claim("code_challenge_method", codeChallengeMethod)
            .claim("redirect_uri", redirectUri)
            .build();
        URI requestUri = URI.create(REQUEST_URI_PREFIX + new State().getValue());
        createSession(requestUri, authorizationRequestClaims);
        long expiresIn = asProperties.ttl().requestUri().toSeconds();
        return ResponseEntity.status(HttpStatus.CREATED).body(new ParResponse(requestUri, expiresIn));
    }

    private void createSession(URI requestUri, JWTClaimsSet requestObjectClaims) throws ParseException {
        sessionRepository.save(Session.builder()
            .requestUri(requestUri)
            .requestUriExpirationTime(Instant.now())
            .requestObjectClaims(requestObjectClaims)
            .build());
    }
}
