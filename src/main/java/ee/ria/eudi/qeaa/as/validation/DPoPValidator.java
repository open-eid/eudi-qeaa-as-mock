package ee.ria.eudi.qeaa.as.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker;
import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Clock;
import java.util.Set;

import static ee.ria.eudi.qeaa.as.controller.TokenController.TOKEN_REQUEST_MAPPING;

@Component
@RequiredArgsConstructor
public class DPoPValidator {
    public static final String JOSE_TYPE_DPOP_JWT = "dpop+jwt";
    private final JwsHeaderKeySelector jwsHeaderKeySelector = new JwsHeaderKeySelector(Set.of(
        JWSAlgorithm.RS256,
        JWSAlgorithm.RS384,
        JWSAlgorithm.RS512,
        JWSAlgorithm.ES256,
        JWSAlgorithm.ES384,
        JWSAlgorithm.ES512,
        JWSAlgorithm.PS256,
        JWSAlgorithm.PS384,
        JWSAlgorithm.PS512
    ));
    private final AuthorizationServerProperties.AuthorizationServer properties;
    private final DefaultDPoPSingleUseChecker dPoPSingleUseChecker;
    @Getter
    private final Clock systemClock = Clock.systemUTC();

    public SignedJWT validate(String dPoPHeader, String expectedIssuer) {
        try {
            SignedJWT dPoPJwt = SignedJWT.parse(dPoPHeader);
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(jwsHeaderKeySelector);
            jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(JOSE_TYPE_DPOP_JWT)));
            jwtProcessor.setJWTClaimsSetVerifier(getClaimsVerifier(expectedIssuer));
            jwtProcessor.process(dPoPJwt, null);
            return dPoPJwt;
        } catch (ParseException | BadJOSEException | JOSEException ex) {
            throw new ServiceException("Invalid DPoP", ex);
        }
    }

    private DPoPClaimsVerifier getClaimsVerifier(String expectedIssuer) {
        return new DPoPClaimsVerifier(
            properties.baseUrl() + TOKEN_REQUEST_MAPPING,
            HttpMethod.POST.name(),
            properties.dPoPExpiryTime().toSeconds(),
            properties.maxClockSkew().toSeconds(),
            new DPoPIssuer(expectedIssuer),
            dPoPSingleUseChecker, getSystemClock());
    }
}
