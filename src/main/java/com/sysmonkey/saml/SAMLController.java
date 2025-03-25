package com.sysmonkey.saml;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.opensaml.saml.saml2.core.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.logging.Logger;

import static com.sysmonkey.saml.SAMLValidator.*;


@RestController
@RequestMapping("/sso")
public class SAMLController {

    private final Logger log = Logger.getLogger(SAMLController.class.getName());
    private final SAMLValidator samlValidator;

    public SAMLController(SAMLValidator samlValidator) {
        this.samlValidator = samlValidator;
    }

    @PostMapping("/acs")
    public ResponseEntity<String> validade(@RequestBody String samlString, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        log.info("Received SAML assertion");
        try {

            String samlDecoded = samlValidator.decodeSamlString(samlString);

            Response response = samlValidator.samlResponse(samlDecoded);

            Assertion assertion = samlValidator.samlAssertion(response);

            samlValidator.validateSignature(assertion);

            samlValidator.validateContent(assertion);

            httpResponse.sendRedirect(samlValidator.redirectURL());

            log.info("SAML assertion valid for user");

            // Optionally, create a user session or token here
            return ResponseEntity
                    .noContent()
                    .build();

        } catch (Exception e) {
            return ResponseEntity
                    .status(500)
                    .body("Error validating SAML assertion: " + e.getMessage());
        }
    }

}
