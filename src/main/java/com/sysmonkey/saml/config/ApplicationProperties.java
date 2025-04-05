package com.sysmonkey.saml.config;

import org.springframework.beans.factory.InitializingBean;

import java.util.logging.Logger;

public class ApplicationProperties implements InitializingBean {

    private static final Logger log = Logger.getLogger(ApplicationProperties.class.getName());

    private String idpIssuerUri;
    private String idpPublicCert;
    private String idpPublicKey;

    private String spEntityId;
    private String spRedirectCallback;
    private String spRedirectLogout;

    public String getIdpIssuerUri() {
        return idpIssuerUri;
    }

    public void setIdpIssuerUri(String idpIssuerUri) {
        this.idpIssuerUri = idpIssuerUri;
    }

    public String getIdpPublicCert() {
        return idpPublicCert;
    }

    public void setIdpPublicCert(String idpPublicCert) {
        this.idpPublicCert = idpPublicCert;
    }

    public String getIdpPublicKey() {
        return idpPublicKey;
    }

    public void setIdpPublicKey(String idpPublicKey) {
        this.idpPublicKey = idpPublicKey;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public void setSpEntityId(String spEntityId) {
        this.spEntityId = spEntityId;
    }

    public String getSpRedirectCallback() {
        return spRedirectCallback;
    }

    public void setSpRedirectCallback(String spRedirectCallback) {
        this.spRedirectCallback = spRedirectCallback;
    }

    public String getSpRedirectLogout() {
        return spRedirectLogout;
    }

    public void setSpRedirectLogout(String spRedirectLogout) {
        this.spRedirectLogout = spRedirectLogout;
    }

    @Override
    public void afterPropertiesSet() {
        log.info(toString());
    }

    @Override
    public String toString() {
        return "ApplicationProperties{" +
               "idpIssuerUri='" + idpIssuerUri + '\'' +
               ", spEntityId='" + spEntityId + '\'' +
               ", spRedirectCallback='" + spRedirectCallback + '\'' +
               ", spRedirectLogout='" + spRedirectLogout + '\'' +
               '}';
    }
}
