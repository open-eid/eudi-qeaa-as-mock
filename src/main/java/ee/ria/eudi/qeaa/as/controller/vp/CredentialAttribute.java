package ee.ria.eudi.qeaa.as.controller.vp;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum CredentialAttribute {
    EU_EUROPA_EC_EUDI_PID_1_FAMILY_NAME(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1, CredentialNamespace.EU_EUROPA_EC_EUDI_PID_1, "family_name"),
    EU_EUROPA_EC_EUDI_PID_1_GIVEN_NAME(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1, CredentialNamespace.EU_EUROPA_EC_EUDI_PID_1, "given_name"),
    EU_EUROPA_EC_EUDI_PID_1_BIRTH_DATE(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1, CredentialNamespace.EU_EUROPA_EC_EUDI_PID_1, "birth_date"),
    EU_EUROPA_EC_EUDI_PID_1_ISSUANCE_DATE(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1, CredentialNamespace.EU_EUROPA_EC_EUDI_PID_1, "issuance_date"),
    EU_EUROPA_EC_EUDI_PID_1_EXPIRY_DATE(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1, CredentialNamespace.EU_EUROPA_EC_EUDI_PID_1, "expiry_date"),
    EU_EUROPA_EC_EUDI_PID_1_ISSUING_AUTHORITY(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1, CredentialNamespace.EU_EUROPA_EC_EUDI_PID_1, "issuing_authority"),
    EU_EUROPA_EC_EUDI_PID_1_ISSUING_COUNTRY(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1, CredentialNamespace.EU_EUROPA_EC_EUDI_PID_1, "issuing_country"),
    EU_EUROPA_EC_EUDI_PID_1_DOCUMENT_NUMBER(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1, CredentialNamespace.EU_EUROPA_EC_EUDI_PID_1, "document_number"),
    EU_EUROPA_EC_EUDI_PID_1_PERSONAL_ADMINISTRATIVE_NUMBER(CredentialDoctype.EU_EUROPA_EC_EUDI_PID_1, CredentialNamespace.EU_EUROPA_EC_EUDI_PID_1, "personal_administrative_number");

    private final CredentialDoctype doctype;
    private final CredentialNamespace namespace;
    private final String uri;

    public String getPresentationDefinitionPath() {
        return "$['" + namespace.getUri() + "']['" + uri + "']";
    }
}
