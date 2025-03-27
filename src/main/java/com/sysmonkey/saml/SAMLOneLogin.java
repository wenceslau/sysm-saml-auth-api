package com.sysmonkey.saml;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.servlet.ServletUtils;
import com.sysmonkey.saml.config.ApplicationProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.felix.http.javaxwrappers.HttpServletRequestWrapper;
import org.apache.felix.http.javaxwrappers.HttpServletResponseWrapper;
import org.springframework.stereotype.Service;


import java.io.IOException;
import java.util.List;
import java.util.Map;

@Service
public class SAMLOneLogin {

    private final ApplicationProperties appProperties;

    public SAMLOneLogin(ApplicationProperties appProperties) {
        this.appProperties = appProperties;
    }

    public void validate(HttpServletRequest request, HttpServletResponse response) throws Exception {

        HttpServletRequestWrapper requestWrapper = new HttpServletRequestWrapper(request);
        HttpServletResponseWrapper responseWrapper = new HttpServletResponseWrapper(response);

        Auth auth = new Auth("onelogin.properties", requestWrapper, responseWrapper);
        auth.processResponse();

        if (!auth.isAuthenticated()) {
            var errors = auth.getErrors();
            var causes = String.join(", ", errors);
            throw new SecurityException("User not authenticated. Errors: " + causes);
        }

    }

    public String redirectURL() {
        return appProperties.getRedirectOnelogin();
    }
}
