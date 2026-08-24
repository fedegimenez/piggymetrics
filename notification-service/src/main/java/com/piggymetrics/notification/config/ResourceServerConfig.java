package com.piggymetrics.notification.config;

import feign.RequestInterceptor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource server (opaque token introspection against auth-service) and client-credentials
 * Feign interceptor, based on the Spring Security 5 OAuth2 support.
 */
@Configuration
public class ResourceServerConfig {

	static final String CLIENT_REGISTRATION_ID = "notification-service";

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
				.csrf(csrf -> csrf.disable())
				.authorizeRequests(requests -> requests
						.antMatchers("/", "/demo").permitAll()
						.anyRequest().authenticated())
				.oauth2ResourceServer(server -> server.opaqueToken(Customizer.withDefaults()))
				.build();
	}

	@Bean
	public OpaqueTokenIntrospector opaqueTokenIntrospector(OAuth2ResourceServerProperties properties,
			RestTemplateBuilder restTemplateBuilder) {
		return new CheckTokenOpaqueTokenIntrospector(properties.getOpaquetoken(), restTemplateBuilder);
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clients,
			OAuth2AuthorizedClientService authorizedClients) {

		OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
				.clientCredentials()
				.build();

		AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(clients, authorizedClients);
		manager.setAuthorizedClientProvider(provider);

		return manager;
	}

	@Bean
	public RequestInterceptor oauth2FeignRequestInterceptor(OAuth2AuthorizedClientManager clientManager) {
		return template -> {
			OAuth2AuthorizedClient client = clientManager.authorize(OAuth2AuthorizeRequest
					.withClientRegistrationId(CLIENT_REGISTRATION_ID)
					.principal(CLIENT_REGISTRATION_ID)
					.build());

			if (client != null) {
				template.header(HttpHeaders.AUTHORIZATION, "Bearer " + client.getAccessToken().getTokenValue());
			}
		};
	}
}
