package ee.ria.eudi.qeaa.as.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import jakarta.persistence.Embeddable;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@Embeddable
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class AuthorizationDetails {
    private String type;
    private String format;
    private String doctype;
    private String credentialConfigurationId;
    private List<String> locations;

    @Builder
    @SuppressWarnings("unchecked")
    public AuthorizationDetails(Map<?, ?> authorizationDetails) {
        type = (String) authorizationDetails.get("type");
        format = (String) authorizationDetails.get("format");
        doctype = (String) authorizationDetails.get("doctype");
        credentialConfigurationId = (String) authorizationDetails.get("credential_configuration_id");
        locations = (List<String>) authorizationDetails.get("locations");
    }
}
