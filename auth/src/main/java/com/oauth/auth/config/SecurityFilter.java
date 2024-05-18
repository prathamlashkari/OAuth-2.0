package com.oauth.auth.config;

import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

public class SecurityFilter {

  public SecurityFilterChain securityFilterChain(HttpSecurity https) throws Exception {

    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(https);

    https.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

    https.exceptionHandling(execp -> {
      execp.defaultAuthenticationEntryPointFor(
          new LoginUrlAuthenticationEntryPoint("/login"),
          new MediaTypeRequestMatcher((MediaType.TEXT_HTML)));
    });

    https.oauth2ResourceServer(server -> {
      server.jwt(Customizer.withDefaults());
    });

    return https.build();
  }

}
