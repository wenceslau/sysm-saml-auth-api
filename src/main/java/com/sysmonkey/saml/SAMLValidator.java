package com.sysmonkey.saml;

import com.sysmonkey.saml.config.ApplicationProperties;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class SAMLValidator {

    private static final Set<String> assertionIds = new HashSet<>();

    static {
        try {
            InitializationService.initialize(); // Initialize OpenSAML
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize OpenSAML", e);
        }
    }

    private final ApplicationProperties appProperties;

    public SAMLValidator(ApplicationProperties appProperties) {
        this.appProperties = appProperties;
    }

    public String decodeSamlString(String samlResponseEncoded) {
        try {
            // Step 1: Extract value after "SAMLResponse="
            String encodedAssertion = samlResponseEncoded.split("SAMLResponse=")[1];

            // Step 2: URL Decode
            String urlDecoded = URLDecoder.decode(encodedAssertion, StandardCharsets.UTF_8);

            // Step 3: Base64 Decode
            byte[] decodedBytes = Base64.getDecoder().decode(urlDecoded);
            return new String(decodedBytes, StandardCharsets.UTF_8);

        } catch (Exception e) {
            throw new SecurityException("Error decoding SAML response", e);
        }
    }

    public Response samlResponse(String samlDecoded) {
        try {
            // Parse the XML String into a Document
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(samlDecoded.getBytes()));
            Element element = document.getDocumentElement();

            // Unmarshall the Document into an Assertion object
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

            if (unmarshaller == null) {
                throw new SecurityException("No Unmarshaller found for element: " + element.getNodeName());
            }

            XMLObject xmlObject = unmarshaller.unmarshall(element);
            return (Response) xmlObject;

        } catch (Exception e) {
            throw new SecurityException("Error parsing SAML response", e);
        }
    }

    public Assertion samlAssertion(Response response) {
        if (response.getAssertions() != null && !response.getAssertions().isEmpty()) {
            return response.getAssertions().get(0);
        }
        throw new SecurityException("No SAML assertion found in the response");
    }

    public void validateSignature(Assertion assertion) {

        try {
            Signature signature = assertion.getSignature();
            if (signature == null) {
                throw new SecurityException("SAML assertion does not contain a signature");
            }

            X509Certificate certificate = buildX509FromCertificate();

            Credential credential = new BasicX509Credential(certificate);
            SignatureValidator.validate(signature, credential);

        } catch (Exception e) {
            throw new SecurityException("Error validating SAML assertion signature: " + e.getMessage(), e);
        }

    }

    public void validateContent(Assertion assertion) {

        /*
            ✅ Digital Signature → Must be valid and signed by Keycloak.
            ✅ Issuer → Must match Keycloak’s URL.
            ✅ Audience → Must match your app’s entity ID.
            ✅ Expiration → Must not be expired.
            ✅ Subject → Must contain valid user info.
            ✅ Authentication Method → Must be secure (e.g., MFA, password).
            ✅ Prevent Replay Attacks → Store Assertion ID and reject reused ones.
            ✅ User Attributes → Must contain required fields (email, roles, etc.).
         */

        String expectedIssuer = appProperties.getIssuerUri();
        if (!expectedIssuer.equals(assertion.getIssuer().getValue())) {
            throw new SecurityException("Invalid SAML Issuer!");
        }

        String expectedAudience = "sysm-saml-auth-ui";
        List<Audience> audiences = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences();
        boolean audienceValid = audiences.stream().anyMatch(a -> expectedAudience.equals(a.getURI()));
        if (!audienceValid) {
            throw new SecurityException("Invalid Audience in SAML Assertion!");
        }

        Instant now = Instant.now();
        Conditions conditions = assertion.getConditions();
        if (conditions.getNotBefore().isAfter(now) || conditions.getNotOnOrAfter().isBefore(now)) {
            throw new SecurityException("SAML Assertion is expired or not yet valid!");
        }

        String subjectName = assertion.getSubject().getNameID().getValue();
        if (subjectName == null || subjectName.isEmpty()) {
            throw new SecurityException("SAML Assertion has no valid subject!");
        }

        AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
        String authnContext = authnStatement.getAuthnContext().getAuthnContextClassRef().getURI();
        if (!"urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".equals(authnContext)) {
            throw new SecurityException("Invalid Authentication Method in SAML Assertion!");
        }

        String assertionID = assertion.getID();
        if (isAssertionAlreadyUsed(assertionID)) {
            throw new SecurityException("SAML Assertion was already used!");
        }
    }

    public String redirectURL() {
        return appProperties.getRedirectSaml();
    }

    // Private helper methods

    private X509Certificate buildX509FromPublicKey() throws CertificateException {
        try {
            String publicKeyString = appProperties.getPublicKey();
            String publicKeyPEM = "-----BEGIN CERTIFICATE-----\n" +
                                       publicKeyString +"\n" +
                                       "-----END CERTIFICATE-----";
            return X509Support.decodeCertificate(publicKeyPEM);

        } catch (Exception e) {
            throw new SecurityException("Error creating X509Certificate from Public Key: " + e.getMessage(), e);
        }
    }

    public X509Certificate buildX509FromCertificate() throws Exception {

        try {
            String certificateString = appProperties.getPublicCert();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            InputStream certificateInputStream;

            certificateInputStream = new ByteArrayInputStream(Base64.getDecoder().decode(certificateString));

            return (X509Certificate) certificateFactory.generateCertificate(certificateInputStream);

        } catch (Exception e) {
            throw new SecurityException("Error creating X509Certificate from certificate: " + e.getMessage(), e);
        }
    }

    private static boolean isAssertionAlreadyUsed(String assertionID) {
        if (assertionIds.contains(assertionID)) {
            return true;
        }
        assertionIds.add(assertionID);
        return false;
    }

}
