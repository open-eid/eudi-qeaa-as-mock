package ee.ria.eudi.qeaa.as.controller;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.net.URI;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record ParResponse(
    URI requestUri,
    long expiresIn) {

}
