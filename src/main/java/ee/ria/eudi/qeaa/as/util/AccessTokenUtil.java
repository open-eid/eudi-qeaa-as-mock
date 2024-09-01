package ee.ria.eudi.qeaa.as.util;

import com.nimbusds.jose.util.Base64URL;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for computing SHA-256 hash of the access token.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449.html#section-4.2">RFC 9449, section-4.2</a>
 */
@UtilityClass
public class AccessTokenUtil {

    public String computeSHA256(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(token.getBytes(StandardCharsets.US_ASCII));
            return Base64URL.encode(hash).toString();
        } catch (NoSuchAlgorithmException e) {
            throw new ServiceException(e);
        }
    }
}
