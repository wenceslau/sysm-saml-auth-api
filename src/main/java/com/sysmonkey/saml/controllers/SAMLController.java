package com.sysmonkey.saml.controllers;

import com.sysmonkey.saml.SAMLOneLogin;
import com.sysmonkey.saml.SAMLValidator;
import com.sysmonkey.saml.config.ApplicationProperties;
import com.sysmonkey.saml.config.JwtTokenConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.RandomStringUtils;
import org.opensaml.saml.saml2.core.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;


@RestController
@RequestMapping("/sso")
public class SAMLController {

    private final Logger log = Logger.getLogger(SAMLController.class.getName());
    private final ApplicationProperties appProperties;
    private final SAMLValidator samlValidator;
    private final SAMLOneLogin samlOneLogin;
    private final JwtTokenConfig jwtTokenConfig;

    public SAMLController(ApplicationProperties appProperties,
                          SAMLValidator samlValidator,
                          SAMLOneLogin samlOneLogin,
                          JwtTokenConfig jwtTokenConfig) {
        this.appProperties = appProperties;
        this.samlValidator = samlValidator;
        this.samlOneLogin = samlOneLogin;
        this.jwtTokenConfig = jwtTokenConfig;
    }

    @GetMapping("/auth-onelogin")
    public ResponseEntity<String> authOneLogin(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        /*
            This method is called when the user clicks the login button.
            It redirects the user to the SAML IdP for authentication.
            I could redirect to the Idp directly using `${this.oauthUrl}/realms/${this.realm}/protocol/saml/clients/${clientId}`
            but in this example, I decided to use the SAMLValidator class to handle the SAML request.
         */
        log.info("SAML login requested");
        try {
            samlOneLogin.authRequest(httpRequest, httpResponse);
            return ResponseEntity
                    .noContent()
                    .build();
        } catch (Exception e) {
            return buildError(httpResponse, e);
        }
    }

    @PostMapping("/acs-onelogin")
    public ResponseEntity<String> acsOnelogin(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        log.info("SAML Response assertion received on ACS-OneLogin");
        try {

            // It is used only on this project, due to I have on the same SP the SAML and OpenID Connect for test
            // It must not be used in production; the ACS should return error in any case when the SAMLResponse is not valid
            if (httpRequest.getParameter("SAMLRequest") != null) {
                httpResponse.sendRedirect(appProperties.getSpRedirectLogout());
                return ResponseEntity
                        .noContent()
                        .build();
            }

            String username = samlOneLogin.authResponse(httpRequest, httpResponse);

            log.info("SAML assertion validated for user on ACS-OneLogin");

            var urlFragment = buildUrlFragment(username, "ACS-OneLogin");
            httpResponse.sendRedirect(appProperties.getSpRedirectCallback() + urlFragment);

            // Optionally, create a user session or token here
            return ResponseEntity
                    .noContent()
                    .build();

        } catch (Exception e) {
            return buildError(httpResponse, e);
        }
    }

    @PostMapping("/acs-validate")
    public ResponseEntity<String> acsValidade(@RequestBody String samlString, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        log.info("SAML Response assertion received on ACS-Validate");
        try {

            // It is used only on this project, due to I have on the same SP the SAML and OpenID Connect for test
            // It must not be used in production; the ACS should return error in any case when the SAMLResponse is not valid
            if (samlString != null && samlString.startsWith("SAMLRequest=")) {
                httpResponse.sendRedirect(appProperties.getSpRedirectLogout());
                return ResponseEntity
                        .noContent()
                        .build();
            }

            String samlDecoded = samlValidator.decodeSamlString(samlString);

            Response response = samlValidator.samlResponse(samlDecoded);

            Assertion assertion = samlValidator.samlAssertion(response);

            samlValidator.validateSignature(assertion);

            samlValidator.validateContent(assertion);

            log.info("SAML assertion validated for user on ACS-Validate");

            var urlFragment = buildUrlFragment(assertion.getSubject().getNameID().getValue(), "ACS-Validate");
            httpResponse.sendRedirect(appProperties.getSpRedirectCallback() + urlFragment);

            log.info("SAML assertion validated for user on ACS-Validate");

            // Optionally, create a user session or token here
            return ResponseEntity
                    .noContent()
                    .build();

        } catch (Exception e) {
            return buildError(httpResponse, e);
        }
    }

    private ResponseEntity<String> buildError(HttpServletResponse httpResponse, Exception e) {
        var message = "Error validating SAML assertion";
        log.log(Level.SEVERE, message, e);
        message += ": " + e.getMessage();

        return ResponseEntity
                .status(500)
                .body(message);
    }

    private String buildUrlFragment(String username, String source) {

        String access_token = jwtTokenConfig.generateToken(username, List.of(""));
        String state = "";
        String nonce = "";
        String session_state = "";
        String id_token = RandomStringUtils.insecure().nextAlphanumeric(32);
        String token_type = "Bearer";
        String expires_in = "";

        String url = "";

        url += "#source=" + source;
        url += "&access_token=" + access_token;
        url += "&state=" + state;
        url += "&nonce=" + nonce;
        url += "&session_state=" + session_state;
        url += "&id_token=" + id_token;
        url += "&token_type=" + token_type;
        url += "&expires_in=" + expires_in;

        return url;
    }

}
