package com.oauth.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@EnableWebSecurity
@Configuration
public class SecurityFilter {

  @Bean
  @Order(1)
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

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity https) throws Exception {
    https.authorizeHttpRequests(
        authorize -> authorize.anyRequest().authenticated()).formLogin(Customizer.withDefaults());

    return https.build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    UserDetails users = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build();
    return (RegisteredClientRepository) new InMemoryUserDetailsManager(users);
  }
}
