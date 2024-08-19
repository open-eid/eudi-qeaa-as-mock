package ee.ria.eudi.qeaa.as.controller.vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;
import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.controller.vp.PresentationDefinition.Field;
import ee.ria.eudi.qeaa.as.controller.vp.PresentationDefinition.InputDescriptor;
import ee.ria.eudi.qeaa.as.controller.vp.VerifierMetadata.MsoMdoc;
import ee.ria.eudi.qeaa.as.controller.vp.VerifierMetadata.VpFormats;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ee.ria.eudi.qeaa.as.controller.vp.PresentationRequestObject.ClientIdScheme.X509_SAN_DNS;
import static ee.ria.eudi.qeaa.as.controller.vp.PresentationRequestObject.ResponseMode.DIRECT_POST_JWT;
import static ee.ria.eudi.qeaa.as.controller.vp.PresentationRequestObject.ResponseType.VP_TOKEN;
import static ee.ria.eudi.qeaa.as.controller.vp.PresentationResponseController.RESPONSE_REQUEST_MAPPING;

@Component
@RequiredArgsConstructor
public class PresentationRequestObjectFactory {
    public static final JOSEObjectType OAUTH_AUTHZ_REQ_JWT = new JOSEObjectType("oauth-authz-req+jwt");

    private final AuthorizationServerProperties authorizationServerProperties;
    private final ECDSASigner asSigner;
    private final ECKey asSigningKey;
    private final JWSAlgorithm asSigningKeyJwsAlg;
    private final String asClientId;
    private final ObjectMapper objectMapper;

    public SignedJWT createPidPresentationRequest(ECKey responseEncryptionKey) throws JOSEException, ParseException {
        PresentationRequestObject requestObject = PresentationRequestObject.builder()
            .clientId(asClientId)
            .clientIdScheme(X509_SAN_DNS)
            .responseType(VP_TOKEN)
            .responseMode(DIRECT_POST_JWT)
            .responseUri(authorizationServerProperties.as().baseUrl() + RESPONSE_REQUEST_MAPPING)
            .clientMetadata(getClientMetadata(responseEncryptionKey))
            .presentationDefinition(getPresentationDefinition())
            .nonce(new Nonce().getValue())
            .state(new State().getValue())
            .build();
        JWSHeader jwsHeader = new JWSHeader.Builder(asSigningKeyJwsAlg)
            .type(OAUTH_AUTHZ_REQ_JWT)
            .x509CertChain(asSigningKey.getX509CertChain())
            .x509CertSHA256Thumbprint(asSigningKey.getX509CertSHA256Thumbprint())
            .build();
        Map<String, Object> claims = objectMapper.convertValue(requestObject, new TypeReference<>() {
        });
        SignedJWT requestObjectJwt = new SignedJWT(jwsHeader, JWTClaimsSet.parse(claims));
        requestObjectJwt.sign(asSigner);
        return requestObjectJwt;
    }

    private PresentationDefinition getPresentationDefinition() {
        Field documentTypeFilter = Field.builder()
            .path(List.of("$.type"))
            .filter(PresentationDefinition.Filter.builder()
                .type("string")
                .pattern(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1.getUri())
                .build())
            .build();
        Field personalIdCodeField = Field.builder()
            .path(List.of(CredentialAttribute.EU_EUROPA_EC_EUDI_PID_EE_1_PERSONAL_IDENTIFICATION_NUMBER.getPresentationDefinitionPath()))
            .build();
        List<Field> fields = List.of(documentTypeFilter, personalIdCodeField);
        PresentationDefinition.Constraints constraints = PresentationDefinition.Constraints.builder()
            .limitDisclosure("required")
            .fields(fields)
            .build();
        InputDescriptor inputDescriptor = InputDescriptor.builder()
            .id(UUID.randomUUID().toString())
            .format(Map.of("mso_mdoc", Map.of("alg", List.of("ES256", "ES384", "ES512", "EdDSA", "ESB256", "ESB320", "ESB384", "ESB512")))) // ISO-23220-4
            .constraints(constraints)
            .build();
        return PresentationDefinition.builder()
            .id(UUID.randomUUID().toString())
            .name("PID presentation request")
            .purpose("User authentication")
            .inputDescriptors(List.of(inputDescriptor))
            .build();
    }

    private VerifierMetadata getClientMetadata(ECKey responseEncryptionKey) throws JOSEException {
        MsoMdoc msoMdoc = MsoMdoc.builder()
            .alg(List.of("ES256", "ES384", "ES512", "EdDSA")) // ISO-23220-4
            .build();
        VpFormats vpFormats = VpFormats.builder()
            .msoMdoc(msoMdoc)
            .build();
        return VerifierMetadata.builder()
            .clientName("Authorization Server")
            .clientUri(authorizationServerProperties.as().baseUrl() + "/info")
            .logoUri(authorizationServerProperties.as().baseUrl() + "/as_logo.png")
            .vpFormats(vpFormats)
            .authorizationEncryptedResponseAlg("ECDH-ES")
            .authorizationEncryptedResponseEnc("A128CBC-HS256")
            .jwks(new JWKSet(responseEncryptionKey.toPublicJWK()).toJSONObject())
            .build();
    }
}
