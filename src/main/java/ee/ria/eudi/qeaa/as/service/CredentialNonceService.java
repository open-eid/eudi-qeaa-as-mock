package ee.ria.eudi.qeaa.as.service;

import com.nimbusds.jwt.SignedJWT;
import ee.ria.eudi.qeaa.as.util.AccessTokenUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.web.client.RestClientSsl;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;

@Service
@RequiredArgsConstructor
public class CredentialNonceService {
    private final RestClient.Builder restClientBuilder;
    private final RestClientSsl ssl;
    private RestClient restClient;

    @PostConstruct
    private void setupRestClient() {
        this.restClient = restClientBuilder.apply(ssl.fromBundle("eudi-as")).build();
    }

    public CredentialNonce requestNonce(String uri, SignedJWT accessToken) {
        String accessTokenHash = AccessTokenUtil.computeSHA256(accessToken.serialize());
        var payload = new LinkedMultiValueMap<>();
        payload.add("ath", accessTokenHash);
        return restClient.post()
            .uri(uri + "/nonce") // TODO: From issuer metadata
            .body(payload)
            .contentType(APPLICATION_FORM_URLENCODED)
            .accept(APPLICATION_JSON)
            .retrieve()
            .body(CredentialNonce.class);
    }
}
