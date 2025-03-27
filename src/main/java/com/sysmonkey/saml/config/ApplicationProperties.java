package com.sysmonkey.saml.config;

import org.springframework.beans.factory.InitializingBean;

import java.util.logging.Logger;

public class ApplicationProperties implements InitializingBean {

    private static final Logger log = Logger.getLogger(ApplicationProperties.class.getName());

    private String issuerUri;
    private String redirectSaml;
    private String redirectOnelogin;
    private String publicCert;
    private String publicKey;

    public String getIssuerUri() {
        return issuerUri;
    }

    public void setIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
    }

    public String getRedirectSaml() {
        return redirectSaml;
    }

    public void setRedirectSaml(String redirectSaml) {
        this.redirectSaml = redirectSaml;
    }

    public String getRedirectOnelogin() {
        return redirectOnelogin;
    }

    public void setRedirectOnelogin(String redirectOnelogin) {
        this.redirectOnelogin = redirectOnelogin;
    }

    public String getPublicCert() {
        return publicCert;
    }

    public void setPublicCert(String publicCert) {
        this.publicCert = publicCert;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        log.info(toString());
    }

    @Override
    public String toString() {
        return "ApplicationProperties{" +
               "issuerUri='" + issuerUri + '\'' +
               ", clientRedirect='" + redirectSaml + '\'' +
               ", publicCert='" + publicCert + '\'' +
               ", publicKey='" + publicKey + '\'' +
               '}';
    }
}
