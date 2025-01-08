package ee.ria.eudi.qeaa.as.validation;

import ee.ria.eudi.qeaa.as.configuration.properties.AuthorizationServerProperties;
import ee.ria.eudi.qeaa.as.controller.vp.CredentialNamespace;
import ee.ria.eudi.qeaa.as.error.ServiceException;
import ee.ria.eudi.qeaa.as.util.MDocUtil;
import id.walt.mdoc.SimpleCOSECryptoProvider;
import id.walt.mdoc.dataretrieval.DeviceResponse;
import id.walt.mdoc.doc.MDoc;
import id.walt.mdoc.mdocauth.DeviceAuthentication;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static ee.ria.eudi.qeaa.as.controller.vp.PresentationResponseController.RESPONSE_REQUEST_MAPPING;
import static ee.ria.eudi.qeaa.as.util.MDocUtil.KEY_ID_DEVICE;
import static ee.ria.eudi.qeaa.as.util.MDocUtil.KEY_ID_ISSUER;

@Slf4j
@Component
@RequiredArgsConstructor
public class VpTokenValidator {
    private final AuthorizationServerProperties.AuthorizationServer asProperties;
    @Qualifier("issuerTrustedRootCAs")
    private final List<X509Certificate> issuerTrustedRootCAs;

    public Map<CredentialNamespace, Map<String, Object>> validateMsoMDoc(String vpToken, String nonce, String mDocNonce) {
        MDoc mDoc = getMDoc(vpToken);
        if (!mDoc.verifyDocType()) {
            throw new ServiceException("Invalid mDoc doctype");
        }
        if (!mDoc.verifyValidity()) {
            throw new ServiceException("Expired mDoc");
        }
        if (!mDoc.verifyIssuerSignedItems()) {
            throw new ServiceException("Invalid mDoc issuer signed items");
        }
        SimpleCOSECryptoProvider issuerCryptoProvider = MDocUtil.getIssuerCryptoProvider(mDoc, issuerTrustedRootCAs);
        if (!mDoc.verifyCertificate(issuerCryptoProvider, KEY_ID_ISSUER)) {
            throw new ServiceException("Invalid mDoc certificate chain");
        }
        if (!mDoc.verifySignature(issuerCryptoProvider, KEY_ID_ISSUER)) {
            throw new ServiceException("Invalid mDoc issuer signature");
        }
        DeviceAuthentication deviceAuthentication = MDocUtil.getDeviceAuthentication(asProperties.clientId(), mDoc.getDocType().getValue(),
            asProperties.baseUrl() + RESPONSE_REQUEST_MAPPING, nonce, mDocNonce);
        log.info("Device authentication for client {} and nonce {} -> cbor hex: {}", asProperties.clientId(), nonce, deviceAuthentication.toDE().toCBORHex());
        SimpleCOSECryptoProvider deviceCryptoProvider = MDocUtil.getDeviceCryptoProvider(mDoc);
        if (!mDoc.verifyDeviceSignature(deviceAuthentication, deviceCryptoProvider, KEY_ID_DEVICE)) {
            throw new ServiceException("Invalid mDoc device signature");
        }
        return MDocUtil.getIssuerSignedItems(mDoc);
    }

    private static MDoc getMDoc(String vpToken) {
        try {
            return getMDocFromDeviceResponse(vpToken);
        } catch (Exception e) {
            return MDoc.Companion.fromCBORHex(vpToken); // TODO: Remove. Needed to support older version of OpenID4VP.
        }
    }

    private static MDoc getMDocFromDeviceResponse(String vpToken) {
        DeviceResponse deviceResponse = DeviceResponse.Companion.fromCBOR(Base64.getUrlDecoder().decode(vpToken));
        if (deviceResponse.getDocumentErrors() != null && !deviceResponse.getDocumentErrors().getValue().isEmpty()) {
            throw new ServiceException("Invalid device response");
        }
        List<MDoc> documents = deviceResponse.getDocuments();
        if (documents.size() != 1) {
            log.warn("Multiple mdoc documents processing from device response is not implemented. Using first document.");
        }
        return documents.getFirst();
    }
}
