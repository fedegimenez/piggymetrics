package com.piggymetrics.notification.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

public class CheckTokenOpaqueTokenIntrospectorTest {

	private static final String INTROSPECTION_URI = "http://auth-service:5000/uaa/oauth/check_token";

	private MockRestServiceServer server;
	private OpaqueTokenAuthenticationProvider provider;

	@BeforeEach
	public void setup() {

		OAuth2ResourceServerProperties.Opaquetoken properties = new OAuth2ResourceServerProperties().getOpaquetoken();
		properties.setIntrospectionUri(INTROSPECTION_URI);
		properties.setClientId("notification-service");
		properties.setClientSecret("password");

		RestTemplate restTemplate = new RestTemplate();
		server = MockRestServiceServer.bindTo(restTemplate).build();

		RestTemplateBuilder builder = mock(RestTemplateBuilder.class);
		when(builder.basicAuthentication(anyString(), anyString())).thenReturn(builder);
		when(builder.build()).thenReturn(restTemplate);

		provider = new OpaqueTokenAuthenticationProvider(
				new CheckTokenOpaqueTokenIntrospector(properties, builder));
	}

	@Test
	public void shouldAuthenticateTokenWithLegacyCheckTokenResponse() {

		server.expect(requestTo(INTROSPECTION_URI))
				.andExpect(content().string("token=token"))
				.andRespond(withSuccess("{\"exp\":1787626116,\"user_name\":\"demo\",\"client_id\":\"browser\","
						+ "\"aud\":\"account\",\"scope\":[\"ui\"]}", MediaType.APPLICATION_JSON));

		Authentication authentication = provider.authenticate(new BearerTokenAuthenticationToken("token"));

		assertEquals("demo", authentication.getName());
		assertTrue(authentication.getAuthorities().stream()
				.anyMatch(authority -> "SCOPE_ui".equals(authority.getAuthority())));
	}

	@Test
	public void shouldFallBackToClientIdWhenTokenHasNoUser() {

		server.expect(requestTo(INTROSPECTION_URI))
				.andRespond(withSuccess("{\"exp\":1787626116,\"client_id\":\"notification-service\","
						+ "\"scope\":[\"server\"]}", MediaType.APPLICATION_JSON));

		Authentication authentication = provider.authenticate(new BearerTokenAuthenticationToken("token"));

		assertEquals("notification-service", authentication.getName());
	}

	@Test
	public void shouldRejectTokenWhenCheckTokenReturnsBadRequest() {

		server.expect(requestTo(INTROSPECTION_URI))
				.andRespond(withStatus(HttpStatus.BAD_REQUEST)
						.contentType(MediaType.APPLICATION_JSON)
						.body("{\"error\":\"invalid_token\"}"));

		assertThrows(InvalidBearerTokenException.class,
				() -> provider.authenticate(new BearerTokenAuthenticationToken("token")));
	}
}
