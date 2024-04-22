package ee.ria.eudi.qeaa.as.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Set;

import static ee.ria.eudi.qeaa.as.controller.ParController.PAR_REQUEST_MAPPING;

@Component
@RequiredArgsConstructor
public class AuthorizationRequestValidator {
    public static final Set<JWSAlgorithm> ACCEPTED_JWS_ALGORITHMS = Set.of(
        JWSAlgorithm.RS256,
        JWSAlgorithm.RS384,
        JWSAlgorithm.RS512,
        JWSAlgorithm.ES256,
        JWSAlgorithm.ES384,
        JWSAlgorithm.ES512,
        JWSAlgorithm.PS256,
        JWSAlgorithm.PS384,
        JWSAlgorithm.PS512
    );
    private final AuthorizationServerProperties.AuthorizationServer asProperties;

    public JWTClaimsSet validate(String requestObject, SignedJWT clientAttestation) {
        try {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(new ClientAttestationKeySelector(clientAttestation, ACCEPTED_JWS_ALGORITHMS));
            jwtProcessor.setJWTClaimsSetVerifier(getClaimsVerifier(clientAttestation.getJWTClaimsSet().getSubject()));
            return jwtProcessor.process(requestObject, null);
        } catch (ParseException | BadJOSEException | JOSEException ex) {
            throw new ServiceException("Invalid authorization request object", ex);
        }
    }

    private DefaultJWTClaimsVerifier<SecurityContext> getClaimsVerifier(String issuer) {
        return new DefaultJWTClaimsVerifier<>(asProperties.baseUrl() + PAR_REQUEST_MAPPING,
            new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(asProperties.baseUrl() + PAR_REQUEST_MAPPING)
                .claim("client_id", issuer)
                .claim("code_challenge_method", "S256")
                .claim("response_type", "code")
                .build(),
            Set.of(JWTClaimNames.ISSUED_AT, JWTClaimNames.EXPIRATION_TIME, JWTClaimNames.JWT_ID,
                "state", "code_challenge", "authorization_details", "redirect_uri")
            // TODO: authorization_details claims validation
        );
    }
}
