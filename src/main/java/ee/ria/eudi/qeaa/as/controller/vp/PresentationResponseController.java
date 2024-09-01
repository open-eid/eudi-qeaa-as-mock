package ee.ria.eudi.qeaa.as.controller.vp;

import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import ee.ria.eudi.qeaa.as.model.Session;
import ee.ria.eudi.qeaa.as.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.UUID;

import static ee.ria.eudi.qeaa.as.controller.vp.PresentationCallbackController.PRESENTATION_CALLBACK_REQUEST_MAPPING;

@RestController
@RequiredArgsConstructor
public class PresentationResponseController {
    public static final String RESPONSE_REQUEST_MAPPING = "/response";
    private final AuthorizationServerProperties authorizationServerProperties;
    private final SessionRepository sessionRepository;

    @PostMapping(path = RESPONSE_REQUEST_MAPPING, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseCodeResponse presentationResponse(@RequestParam(name = "vp_token") String vpToken,
                                                     @RequestParam(name = "presentation_submission") String presentationSubmission,
                                                     @RequestParam(name = "state") String state) {
        Session session = sessionRepository.findByPresentationRequestState(state).orElseThrow(() -> new ServiceException("Session not found"));
        String responseCode = UUID.randomUUID().toString();
        session.setPresentationResponse(PresentationResponse.builder()
            .vpToken(vpToken)
            .presentationSubmission(presentationSubmission)
            .responseCode(responseCode)
            .build());
        sessionRepository.save(session);
        URI redirectUri = UriComponentsBuilder.fromUriString(authorizationServerProperties.as().baseUrl() + PRESENTATION_CALLBACK_REQUEST_MAPPING)
            .queryParam("response_code", responseCode)
            .build().toUri();
        return ResponseCodeResponse.builder().redirectUri(redirectUri).build();
    }
}
