package com.sysmonkey.saml.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ApplicationConfig {

    @Bean
    @ConfigurationProperties("saml")
    public ApplicationProperties applicationProperties() {
        return new ApplicationProperties();
    }

}
