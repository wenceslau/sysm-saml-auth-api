package com.sysmonkey.saml;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.authn.AuthnRequestParams;
import com.sysmonkey.saml.config.ApplicationProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.felix.http.javaxwrappers.HttpServletRequestWrapper;
import org.apache.felix.http.javaxwrappers.HttpServletResponseWrapper;
import org.springframework.stereotype.Service;


@Service
public class SAMLOneLogin {


    public void authRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(request);
        HttpServletResponseWrapper responseWrapper = new HttpServletResponseWrapper(response);

        // Create the Auth object
        Auth auth = new Auth("onelogin.properties", requestWrapper, responseWrapper);

        // Create the parameters for the AuthnRequest. Although the keycloak does not support forceAuthn
        var authnRequestParams = new AuthnRequestParams(true,false,false);

        // Redirect the user to the SSO URL with ForceAuthn
        String redirectUrl  = auth.login(null, authnRequestParams, true);

        responseWrapper.sendRedirect(redirectUrl);
    }

    public String authResponse(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(request);
        HttpServletResponseWrapper responseWrapper = new HttpServletResponseWrapper(response);

        Auth auth = new Auth("onelogin.properties", requestWrapper, responseWrapper);
        auth.processResponse();

        if (!auth.isAuthenticated()) {
            var errors = auth.getErrors();
            var causes = String.join(", ", errors);
            throw new SecurityException("User not authenticated. Errors: " + causes);
        }

        return auth.getNameId();

    }

}
