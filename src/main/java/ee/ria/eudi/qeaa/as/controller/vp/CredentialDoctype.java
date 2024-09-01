package ee.ria.eudi.qeaa.as.controller.vp;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CredentialDoctype {
    EU_EUROPA_EC_EUDI_PID_1("eu.europa.ec.eudi.pid.1");

    private final String uri;
}
