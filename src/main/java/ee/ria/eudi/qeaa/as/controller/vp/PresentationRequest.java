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

import java.time.Instant;

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
    private String presentationDefinitionId;
    private String state;
    private String nonce;
}
