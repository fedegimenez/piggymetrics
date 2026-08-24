package com.piggymetrics.notification.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Introspects opaque tokens against the legacy {@code /oauth/check_token} endpoint exposed by
 * auth-service, which predates RFC 7662 (no {@code active} claim, principal name in
 * {@code user_name}), so the Nimbus based introspector shipped with Spring Security cannot be used.
 */
public class CheckTokenOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

	private static final String USER_NAME_CLAIM = "user_name";
	private static final String CLIENT_ID_CLAIM = "client_id";
	private static final String SCOPE_CLAIM = "scope";
	private static final String AUTHORITY_PREFIX = "SCOPE_";

	private final String introspectionUri;
	private final RestTemplate restTemplate;

	public CheckTokenOpaqueTokenIntrospector(OAuth2ResourceServerProperties.Opaquetoken properties,
			RestTemplateBuilder restTemplateBuilder) {
		this.introspectionUri = properties.getIntrospectionUri();
		this.restTemplate = restTemplateBuilder
				.basicAuthentication(properties.getClientId(), properties.getClientSecret())
				.build();
	}

	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {

		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("token", token);

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		Map<String, Object> claims;
		try {
			claims = restTemplate.exchange(introspectionUri, HttpMethod.POST, new HttpEntity<>(body, headers),
					new ParameterizedTypeReference<Map<String, Object>>() {
					}).getBody();
		} catch (RestClientException e) {
			throw new OAuth2IntrospectionException("Unable to introspect token", e);
		}

		if (claims == null || claims.containsKey("error") || Boolean.FALSE.equals(claims.get("active"))) {
			throw new BadOpaqueTokenException("Provided token is not active");
		}

		return new DefaultOAuth2AuthenticatedPrincipal(principalName(claims), claims, authorities(claims));
	}

	private String principalName(Map<String, Object> claims) {
		Object name = claims.getOrDefault(USER_NAME_CLAIM, claims.get(CLIENT_ID_CLAIM));
		return name == null ? null : name.toString();
	}

	private Collection<GrantedAuthority> authorities(Map<String, Object> claims) {

		Collection<GrantedAuthority> authorities = new ArrayList<>();
		Object scopes = claims.get(SCOPE_CLAIM);

		if (scopes instanceof String) {
			scopes = List.of(((String) scopes).split(" "));
		}

		if (scopes instanceof Collection) {
			((Collection<?>) scopes).forEach(scope -> authorities.add(new SimpleGrantedAuthority(AUTHORITY_PREFIX + scope)));
		}

		return authorities;
	}
}
