package ee.ria.eudi.qeaa.as.controller.vp;

import ee.ria.eudi.qeaa.as.error.ServiceException;
import ee.ria.eudi.qeaa.as.model.Session;
import ee.ria.eudi.qeaa.as.repository.SessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequiredArgsConstructor
public class PresentationRequestController {
    public static final String PRESENTATION_REQUEST_MAPPING = "/request.jwt";
    public static final String PRESENTATION_REQUEST_URI_ID_MAPPING = PRESENTATION_REQUEST_MAPPING + "/{requestUriId}";
    public static final String APPLICATION_OAUTH_AUTHZ_REQ_JWT = "application/oauth-authz-req+jwt";
    private final SessionRepository sessionRepository;

    @GetMapping(path = PRESENTATION_REQUEST_URI_ID_MAPPING, produces = APPLICATION_OAUTH_AUTHZ_REQ_JWT)
    public String presentationRequest(@PathVariable("requestUriId") String requestUriId) {
        return sessionRepository.findByPresentationRequestRequestUriId(requestUriId)
            .map(Session::getPresentationRequest)
            .filter(ro -> ro.getExpiryTime().isAfter(Instant.now()))
            .map(PresentationRequest::getValue)
            .orElseThrow(() -> new ServiceException("Presentation request object not found"));
    }
}
