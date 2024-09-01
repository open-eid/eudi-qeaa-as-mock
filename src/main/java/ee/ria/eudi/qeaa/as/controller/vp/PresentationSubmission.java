package ee.ria.eudi.qeaa.as.controller.vp;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;

import java.util.List;

@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record PresentationSubmission(
    String id,
    String definitionId,
    List<InputDescriptor> descriptorMap) {

    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record InputDescriptor(
        String id,
        String format,
        String path,
        PathNested pathNested) {
    }

    @Builder
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record PathNested(
        String path,
        String format) {
    }
}

