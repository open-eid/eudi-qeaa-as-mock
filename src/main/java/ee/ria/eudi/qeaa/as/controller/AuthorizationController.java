package ee.ria.eudi.qeaa.as.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.controller.vp.PresentationRequestObjectFactory;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import ee.ria.eudi.qeaa.as.model.Session;
import ee.ria.eudi.qeaa.as.model.vp.PresentationRequest;
import ee.ria.eudi.qeaa.as.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.UUID;

import static ee.ria.eudi.qeaa.as.controller.vp.PresentationRequestController.PRESENTATION_REQUEST_MAPPING;

@RestController
@RequiredArgsConstructor
public class AuthorizationController {
    public static final String AUTHORIZE_REQUEST_MAPPING = "/authorize";
    private final SessionRepository sessionRepository;
    private final PresentationRequestObjectFactory presentationRequestObjectFactory;
    private final AuthorizationServerProperties authorizationServerProperties;
    private final String asClientId;
    @Value("${eudi.wallet.authorization-url}")
    private String walletAuthorizationUrl;

    @GetMapping(path = AUTHORIZE_REQUEST_MAPPING)
    public ResponseEntity<Void> authorize(@RequestParam(name = "client_id") String clientId,
                                          @RequestParam(name = "request_uri") String requestUri) throws JOSEException, ParseException {
        Session session = validateAuthorizationRequest(clientId, requestUri);
        return startPidAuthenticationFlow(session);
    }

    private Session validateAuthorizationRequest(String clientId, String requestUri) {
        Session session = sessionRepository.findByClientIdAndRequestUriAndRequestUriUsed(clientId, requestUri, false)
            .orElseThrow(() -> new ServiceException("Session not found"));
        if (session.isRequestUriExpired()) {
            throw new ServiceException("Authorization request expired");
        }
        session.setRequestUriUsed(true);
        sessionRepository.save(session);
        return session;
    }

    private ResponseEntity<Void> startPidAuthenticationFlow(Session session) throws JOSEException, ParseException {
        String presentationRequestUriId = createPidPresentationRequest(session);
        URI redirectUri = UriComponentsBuilder.fromUriString(walletAuthorizationUrl)
            .queryParam("request_uri", authorizationServerProperties.as().baseUrl() + PRESENTATION_REQUEST_MAPPING + "/" + presentationRequestUriId)
            .queryParam("client_id", asClientId)
            .build().toUri();
        return ResponseEntity.status(HttpStatus.FOUND).location(redirectUri).build();
    }

    private String createPidPresentationRequest(Session session) throws JOSEException, ParseException {
        String presentationRequestUriId = UUID.randomUUID().toString();
        String presentationDefinitionId = UUID.randomUUID().toString();
        SignedJWT pidPresentationRequest = presentationRequestObjectFactory.createPidPresentationRequest(presentationDefinitionId);
        JWTClaimsSet presentationRequestClaims = pidPresentationRequest.getJWTClaimsSet();
        session.setPresentationRequest(PresentationRequest.builder()
            .requestUriId(presentationRequestUriId)
            .value(pidPresentationRequest.serialize())
            .presentationDefinitionId(presentationDefinitionId)
            .state(presentationRequestClaims.getStringClaim("state"))
            .nonce(presentationRequestClaims.getStringClaim("nonce"))
            .expiryTime(Instant.now().plusSeconds(authorizationServerProperties.as().ttl().requestUri().toSeconds()))
            .build());
        sessionRepository.save(session);
        return presentationRequestUriId;
    }
}
