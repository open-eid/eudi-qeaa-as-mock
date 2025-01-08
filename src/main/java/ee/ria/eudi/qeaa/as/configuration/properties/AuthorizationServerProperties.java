package ee.ria.eudi.qeaa.as.configuration.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.hibernate.validator.constraints.time.DurationMax;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "eudi")
public record AuthorizationServerProperties(
    AuthorizationServer as) {

    @ConfigurationProperties(prefix = "eudi.as")
    public record AuthorizationServer(
        @NotBlank
        String clientId,
        @NotBlank
        @Pattern(regexp = ".*(?<!/)$")
        String baseUrl,
        @NotNull
        @DurationMin(seconds = 1)
        @DurationMax(seconds = 120)
        @NotNull
        Duration maxClockSkew,
        @NotNull
        Duration dPoPExpiryTime,
        @NotNull
        TimeToLive ttl) {
    }

    public record TimeToLive(
        @NotNull
        Duration accessToken,
        @NotNull
        Duration requestUri) {
    }
}
