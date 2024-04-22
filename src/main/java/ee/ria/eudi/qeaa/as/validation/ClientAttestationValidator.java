package ee.ria.eudi.qeaa.as.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.stereotype.Component;

import java.security.KeyStore;
import java.text.ParseException;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class ClientAttestationValidator {
    public static final String JOSE_TYPE_WALLET_ATTESTATION_JWT = "wallet-attestation+jwt";
    public static final String JOSE_TYPE_WALLET_ATTESTATION_POP_JWT = "wallet-attestation-pop+jwt";
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
    private final KeyStore walletProviderTruststore;

    public Pair<SignedJWT, SignedJWT> validate(String clientAssertion, String audience) throws ParseException {
        String[] clientAssertions = clientAssertion.split("~");
        SignedJWT clientAttestation = SignedJWT.parse(clientAssertions[0]);
        SignedJWT clientAttestationPoP = SignedJWT.parse(clientAssertions[1]);
        JWTClaimsSet claimsSet = validateClientAttestation(clientAttestation);
        validateClientAttestationPoP(clientAttestation, clientAttestationPoP, audience, claimsSet);
        return Pair.of(clientAttestation, clientAttestationPoP);
    }

    private JWTClaimsSet validateClientAttestation(SignedJWT clientAttestation) {
        try {
            ConfigurableJWTProcessor<SecurityContext> clientAttestationJwtProcessor = new DefaultJWTProcessor<>();
            clientAttestationJwtProcessor.setJWSKeySelector(new X5ChainKeySelector(walletProviderTruststore, ACCEPTED_JWS_ALGORITHMS));
            clientAttestationJwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(JOSE_TYPE_WALLET_ATTESTATION_JWT)));
            clientAttestationJwtProcessor.setJWTClaimsSetVerifier(getClientAttestationClaimsVerifier());
            return clientAttestationJwtProcessor.process(clientAttestation, null);
        } catch (BadJOSEException | JOSEException ex) {
            throw new ServiceException("Invalid client attestation", ex);
        }
    }

    private void validateClientAttestationPoP(SignedJWT clientAttestation, SignedJWT clientAttestationPoP, String audience, JWTClaimsSet claimsSet) {
        try {
            ConfigurableJWTProcessor<SecurityContext> clientAttestationPoPJwtProcessor = new DefaultJWTProcessor<>();
            clientAttestationPoPJwtProcessor.setJWSKeySelector(new ClientAttestationKeySelector(clientAttestation, ACCEPTED_JWS_ALGORITHMS));
            clientAttestationPoPJwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType(JOSE_TYPE_WALLET_ATTESTATION_POP_JWT)));
            clientAttestationPoPJwtProcessor.setJWTClaimsSetVerifier(getClientAttestationPoPClaimsVerifier(audience, claimsSet.getSubject()));
            clientAttestationPoPJwtProcessor.process(clientAttestationPoP, null);
        } catch (BadJOSEException | JOSEException ex) {
            throw new ServiceException("Invalid client attestation PoP", ex);
        }
    }

    private DefaultJWTClaimsVerifier<SecurityContext> getClientAttestationClaimsVerifier() {
        return new DefaultJWTClaimsVerifier<>(
            null,
            Set.of(JWTClaimNames.ISSUER, JWTClaimNames.SUBJECT, JWTClaimNames.ISSUED_AT, JWTClaimNames.EXPIRATION_TIME, "cnf")
        );
    }

    private DefaultJWTClaimsVerifier<SecurityContext> getClientAttestationPoPClaimsVerifier(String audience, String issuer) {
        return new DefaultJWTClaimsVerifier<>(
            audience,
            new JWTClaimsSet.Builder()
                .issuer(issuer)
                .build(),
            Set.of(JWTClaimNames.EXPIRATION_TIME, JWTClaimNames.JWT_ID)
        );
    }
}
