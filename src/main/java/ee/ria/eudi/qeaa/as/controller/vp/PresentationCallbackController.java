package ee.ria.eudi.qeaa.as.controller.vp;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import ee.ria.eudi.qeaa.as.model.Session;
import ee.ria.eudi.qeaa.as.repository.SessionRepository;
import ee.ria.eudi.qeaa.as.validation.VpTokenValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

import static ee.ria.eudi.qeaa.as.controller.vp.CredentialAttribute.EU_EUROPA_EC_EUDI_PID_EE_1_PERSONAL_IDENTIFICATION_NUMBER;
import static ee.ria.eudi.qeaa.as.controller.vp.CredentialNamespace.EU_EUROPA_EC_EUDI_PID_EE_1;

@RestController
@RequiredArgsConstructor
public class PresentationCallbackController {
    public static final String PRESENTATION_CALLBACK_REQUEST_MAPPING = "/presentation-callback";
    private final SessionRepository sessionRepository;
    private final VpTokenValidator vpTokenValidator;

    @GetMapping(PRESENTATION_CALLBACK_REQUEST_MAPPING)
    public ResponseEntity<Void> presentationCallback(@RequestParam(name = "response_code") String responseCode) {
        Session session = sessionRepository.findByPresentationResponseResponseCode(responseCode).orElseThrow(() -> new ServiceException("Session not found"));
        PresentationRequest presentationRequest = session.getPresentationRequest();
        PresentationResponse presentationResponse = session.getPresentationResponse();
        Map<CredentialNamespace, Map<String, Object>> vpTokenClaims = vpTokenValidator.validate(presentationResponse.getVpToken(),
            presentationResponse.getPresentationSubmission(),
            presentationRequest.getPresentationDefinitionId(),
            presentationRequest.getNonce());
        Object subject = vpTokenClaims.getOrDefault(EU_EUROPA_EC_EUDI_PID_EE_1, Collections.emptyMap()).get(EU_EUROPA_EC_EUDI_PID_EE_1_PERSONAL_IDENTIFICATION_NUMBER.getUri());
        if (subject == null) {
            throw new ServiceException("Unable to authenticate user");
        }
        session.setSubject((String) subject);
        return continueAuthorizationCodeFlow(session);
    }

    private ResponseEntity<Void> continueAuthorizationCodeFlow(Session session) {
        session.setAuthorizationCode(new AuthorizationCode().getValue());
        sessionRepository.save(session);
        URI redirectUri = UriComponentsBuilder.fromUriString(session.getRedirectUri())
            .queryParam("state", session.getState())
            .queryParam("code", session.getAuthorizationCode())
            .build().toUri();
        return ResponseEntity.status(HttpStatus.FOUND).location(redirectUri).build();
    }

}
