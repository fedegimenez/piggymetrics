package com.piggymetrics.notification.config;

import feign.RequestInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

/**
 * @author cdov
 */
@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

	@Value("${security.oauth2.client.client-id}")
	private String clientId;

	@Value("${security.oauth2.client.client-secret}")
	private String clientSecret;

	@Value("${security.oauth2.resource.check-token-uri}")
	private String checkTokenUri;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, OpaqueTokenIntrospector introspector) throws Exception {
		return http
				.csrf().disable()
				.authorizeRequests(requests -> requests
						.antMatchers("/actuator/**").permitAll()
						.anyRequest().authenticated())
				.oauth2ResourceServer(server -> server.opaqueToken(token -> token.introspector(introspector)))
				.build();
	}

	@Bean
	public OpaqueTokenIntrospector opaqueTokenIntrospector(RestTemplateBuilder builder) {
		RestTemplate restTemplate = builder.basicAuthentication(clientId, clientSecret).build();
		return new CheckTokenOpaqueTokenIntrospector(checkTokenUri, restTemplate);
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clients,
																 OAuth2AuthorizedClientService clientService) {

		AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
				new AuthorizedClientServiceOAuth2AuthorizedClientManager(clients, clientService);
		manager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder()
				.clientCredentials()
				.build());

		return manager;
	}

	/**
	 * Propagates a client credentials access token to the downstream services called through Feign.
	 */
	@Bean
	public RequestInterceptor oauth2FeignRequestInterceptor(OAuth2AuthorizedClientManager clientManager) {
		return template -> {

			OAuth2AuthorizedClient client = clientManager.authorize(OAuth2AuthorizeRequest
					.withClientRegistrationId(clientId)
					.principal(clientId)
					.build());

			if (client != null) {
				template.header(HttpHeaders.AUTHORIZATION, "Bearer " + client.getAccessToken().getTokenValue());
			}
		};
	}
}
