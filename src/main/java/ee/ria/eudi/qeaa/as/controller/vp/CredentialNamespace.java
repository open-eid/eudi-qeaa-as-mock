package ee.ria.eudi.qeaa.as.controller.vp;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum CredentialNamespace {
    EU_EUROPA_EC_EUDI_PID_1("eu.europa.ec.eudi.pid.1"),
    EU_EUROPA_EC_EUDI_PID_EE_1("eu.europa.ec.eudi.pid.ee.1");

    private final String uri;

    public static CredentialNamespace fromUri(String uri) {
        return Arrays.stream(CredentialNamespace.values())
            .filter(e -> e.getUri().equals(uri))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("No constant with uri " + uri));
    }
}
