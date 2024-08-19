package ee.ria.eudi.qeaa.as.controller.vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import ee.ria.eudi.qeaa.as.controller.vp.PresentationSubmission.InputDescriptor;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import ee.ria.eudi.qeaa.as.model.Session;
import ee.ria.eudi.qeaa.as.repository.SessionRepository;
import ee.ria.eudi.qeaa.as.validation.VpTokenValidator;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.NotImplementedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static ee.ria.eudi.qeaa.as.controller.vp.CredentialAttribute.EU_EUROPA_EC_EUDI_PID_EE_1_PERSONAL_IDENTIFICATION_NUMBER;
import static ee.ria.eudi.qeaa.as.controller.vp.CredentialNamespace.EU_EUROPA_EC_EUDI_PID_EE_1;
import static ee.ria.eudi.qeaa.as.controller.vp.PresentationSubmission.InputDescriptor.CREDENTIAL_FORMAT_MSO_MDOC;
import static ee.ria.eudi.qeaa.as.controller.vp.PresentationSubmission.InputDescriptor.CREDENTIAL_PATH_AS_DIRECT_VP_TOKEN_VALUE;

@RestController
@RequiredArgsConstructor
public class PresentationCallbackController {
    public static final String PRESENTATION_CALLBACK_REQUEST_MAPPING = "/presentation-callback";
    private final SessionRepository sessionRepository;
    private final VpTokenValidator vpTokenValidator;
    private final ObjectMapper objectMapper;

    @GetMapping(PRESENTATION_CALLBACK_REQUEST_MAPPING)
    public ResponseEntity<Void> presentationCallback(@RequestParam(name = "response_code") String responseCode) throws ParseException, JOSEException {
        Session session = sessionRepository.findByPresentationResponseResponseCode(responseCode).orElseThrow(() -> new ServiceException("Session not found"));
        PresentationRequest presentationRequest = session.getPresentationRequest();
        PresentationResponse presentationResponse = session.getPresentationResponse();

        EncryptedJWT jwe = decryptResponseObject(presentationResponse.getResponse(), session.getResponseEncryptionKey());
        JWEHeader header = jwe.getHeader();
        JWTClaimsSet claimsSet = jwe.getJWTClaimsSet();
        Map<String, Object> presentationSubmission = claimsSet.getJSONObjectClaim("presentation_submission");
        validatePresentationSubmission(presentationRequest.getPresentationDefinition(), presentationSubmission);
        String vpToken = claimsSet.getStringClaim("vp_token");
        String mdocNonce = header.getAgreementPartyUInfo().decodeToString();
        Map<CredentialNamespace, Map<String, Object>> vpTokenClaims = vpTokenValidator.validateMsoMDoc(vpToken, presentationRequest.getNonce(), mdocNonce);
        Object subject = vpTokenClaims.getOrDefault(EU_EUROPA_EC_EUDI_PID_EE_1, Collections.emptyMap()).get(EU_EUROPA_EC_EUDI_PID_EE_1_PERSONAL_IDENTIFICATION_NUMBER.getUri());
        if (subject == null) {
            throw new ServiceException("Unable to authenticate user");
        }
        session.setSubject((String) subject);
        return continueAuthorizationCodeFlow(session);
    }

    private EncryptedJWT decryptResponseObject(String responseObject, ECKey responseEncryptionKey) throws ParseException, JOSEException {
        EncryptedJWT jwe = EncryptedJWT.parse(responseObject);
        ECDHDecrypter ecdhDecrypter = new ECDHDecrypter(responseEncryptionKey);
        jwe.decrypt(ecdhDecrypter);
        return jwe;
    }

    private void validatePresentationSubmission(Map<String, Object> presentationDefinition, Map<String, Object> presentationSubmission) {
        PresentationDefinition pd = objectMapper.convertValue(presentationDefinition, PresentationDefinition.class);
        PresentationSubmission ps = objectMapper.convertValue(presentationSubmission, PresentationSubmission.class);
        if (!pd.id().equals(ps.definitionId())) {
            throw new ServiceException("Invalid presentation submission definition id");
        }
        List<InputDescriptor> psInputDescriptors = ps.descriptorMap();
        if (psInputDescriptors == null || pd.inputDescriptors().size() != psInputDescriptors.size()) {
            throw new ServiceException("Invalid presentation submission. Invalid input descriptors.");
        }

        InputDescriptor inputDescriptor = psInputDescriptors.getFirst();
        if (CREDENTIAL_FORMAT_MSO_MDOC.equals(inputDescriptor.format())) {
            if (!CREDENTIAL_PATH_AS_DIRECT_VP_TOKEN_VALUE.equals(inputDescriptor.path())) {
                throw new ServiceException("Invalid credential path. Expecting credential directly in the vp_token element.");
            }
        } else {
            throw new NotImplementedException("Credential format '%s' processing not implemented.".formatted(inputDescriptor.format()));
        }
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
