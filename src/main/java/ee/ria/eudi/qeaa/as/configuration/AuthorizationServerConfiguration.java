package ee.ria.eudi.qeaa.as.configuration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker;
import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.util.JwtUtil;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

@Configuration
@ConfigurationPropertiesScan
public class AuthorizationServerConfiguration {

    @Bean
    public X509Certificate asCert(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("eudi-as");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        return (X509Certificate) keyStore.getCertificate(bundle.getKey().getAlias());
    }

    @Bean
    public ECKey asSigningKey(SslBundles sslBundle) throws KeyStoreException, JOSEException {
        SslBundle bundle = sslBundle.getBundle("eudi-as");
        SslStoreBundle stores = bundle.getStores();
        return ECKey.load(stores.getKeyStore(), bundle.getKey().getAlias(), null);
    }

    @Bean
    public JWSAlgorithm asSigningKeyJwsAlg(ECKey asSigningKey) {
        return JwtUtil.getJwsAlgorithm(asSigningKey.getCurve());
    }

    @Bean
    public ECDSASigner asSigner(ECKey asSigningKey) throws JOSEException {
        return new ECDSASigner(asSigningKey);
    }

    @Bean
    public DefaultDPoPSingleUseChecker dPoPSingleUseChecker(AuthorizationServerProperties.AuthorizationServer as) {
        long ttl = as.dPoPExpiryTime().toSeconds() + as.maxClockSkew().toSeconds();
        return new DefaultDPoPSingleUseChecker(ttl, ttl);
    }
}
