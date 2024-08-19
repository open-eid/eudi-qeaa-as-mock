package ee.ria.eudi.qeaa.as.controller.vp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;

@Entity
@Table(name = "presentation_requests")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PresentationRequest {

    @Id
    private String requestUriId;
    @Lob
    @Column(name = "request_object_value")
    private String value;
    private Instant expiryTime;
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> presentationDefinition;
    private String state;
    private String nonce;
}
