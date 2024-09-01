package ee.ria.eudi.qeaa.as.model;

import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.eudi.qeaa.as.controller.vp.PresentationRequest;
import ee.ria.eudi.qeaa.as.controller.vp.PresentationResponse;
import jakarta.persistence.CascadeType;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "sessions")
@Data
@NoArgsConstructor
public class Session {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String requestUri;
    private boolean requestUriUsed;
    private Instant requestUriExpirationTime;
    private String state;
    private String clientId;
    private String codeChallenge;
    private String codeChallengeMethod;
    private String redirectUri;
    private String authorizationCode;
    private boolean authorizationCodeUsed;
    @ElementCollection
    private List<AuthorizationDetails> authorizationDetails;
    @OneToOne(cascade = CascadeType.ALL)
    private PresentationRequest presentationRequest;
    @OneToOne(cascade = CascadeType.ALL)
    private PresentationResponse presentationResponse;
    private String subject;

    @Builder
    public Session(URI requestUri, Instant requestUriExpirationTime, JWTClaimsSet requestObjectClaims) throws ParseException {
        this.requestUri = requestUri.toString();
        this.requestUriExpirationTime = requestUriExpirationTime;
        state = requestObjectClaims.getStringClaim("state");
        clientId = requestObjectClaims.getStringClaim("client_id");
        codeChallenge = requestObjectClaims.getStringClaim("code_challenge");
        codeChallengeMethod = requestObjectClaims.getStringClaim("code_challenge_method");
        redirectUri = requestObjectClaims.getStringClaim("redirect_uri");
        authorizationDetails = requestObjectClaims.getListClaim("authorization_details")
            .stream()
            .filter(Map.class::isInstance)
            .map(ad -> (Map<?, ?>) ad)
            .map(m -> AuthorizationDetails.builder()
                .authorizationDetails(m)
                .build())
            .toList();
    }

    public boolean isRequestUriExpired() {
        return requestUriExpirationTime.isAfter(Instant.now());
    }
}

