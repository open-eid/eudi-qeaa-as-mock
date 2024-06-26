package ee.ria.eudi.qeaa.as.util;

import ee.ria.eudi.qeaa.as.error.ServiceException;
import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@UtilityClass
public class X509CertUtil {

    public String getSubjectAlternativeNameDNSName(X509Certificate x509Certificate) {
        byte[] extensionValue = x509Certificate.getExtensionValue("2.5.29.17");
        if (extensionValue == null) {
            throw new ServiceException("SAN extension not found.");
        }
        try {
            ASN1Encodable asn1Encodable = ASN1Primitive.fromByteArray(extensionValue);
            if (asn1Encodable instanceof ASN1OctetString octetString) {
                asn1Encodable = ASN1Primitive.fromByteArray(octetString.getOctets());
            } else {
                throw new ServiceException("SAN extension not found.");
            }
            GeneralNames names = GeneralNames.getInstance(asn1Encodable);
            return Arrays.stream(names.getNames())
                .filter(name -> name.getTagNo() == GeneralName.dNSName)
                .map(name -> name.getName().toString())
                .findFirst()
                .orElseThrow(() -> new ServiceException("DNS name not found in SAN."));
        } catch (IOException e) {
            throw new ServiceException("Unable to parse SAN extension not found.", e);
        }
    }
}
