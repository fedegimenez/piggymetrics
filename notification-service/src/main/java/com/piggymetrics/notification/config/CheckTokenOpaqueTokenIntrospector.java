package com.piggymetrics.notification.config;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Introspects opaque tokens against the legacy {@code /oauth/check_token} endpoint exposed by
 * auth-service, which predates RFC 7662 and answers with the token claims (or an error) instead
 * of an {@code active} flag.
 */
public class CheckTokenOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

	private static final String SCOPE_AUTHORITY_PREFIX = "SCOPE_";

	private final String checkTokenUri;
	private final RestTemplate restTemplate;

	public CheckTokenOpaqueTokenIntrospector(String checkTokenUri, RestTemplate restTemplate) {
		this.checkTokenUri = checkTokenUri;
		this.restTemplate = restTemplate;
	}

	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {

		Map<String, Object> claims = checkToken(token);
		if (claims.containsKey("error")) {
			throw new BadOpaqueTokenException("Provided token is not active: " + claims.get("error"));
		}

		return new OAuth2IntrospectionAuthenticatedPrincipal(principalName(claims), claims, authorities(claims));
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> checkToken(String token) {

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

		MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
		body.add("token", token);

		try {
			return restTemplate.postForObject(checkTokenUri,
					new org.springframework.http.HttpEntity<>(body, headers), Map.class);
		} catch (HttpClientErrorException e) {
			throw new BadOpaqueTokenException("Provided token is not active", e);
		} catch (RestClientException e) {
			throw new OAuth2IntrospectionException("Unable to introspect token", e);
		}
	}

	private String principalName(Map<String, Object> claims) {
		Object userName = claims.get("user_name");
		return userName != null ? userName.toString() : String.valueOf(claims.get("client_id"));
	}

	private Collection<GrantedAuthority> authorities(Map<String, Object> claims) {

		Collection<GrantedAuthority> authorities = new ArrayList<>();

		toStringList(claims.get("scope")).forEach(scope ->
				authorities.add(new SimpleGrantedAuthority(SCOPE_AUTHORITY_PREFIX + scope)));
		toStringList(claims.get("authorities")).forEach(authority ->
				authorities.add(new SimpleGrantedAuthority(authority)));

		return authorities;
	}

	private List<String> toStringList(Object value) {

		if (value instanceof Collection) {
			return ((Collection<?>) value).stream().map(String::valueOf).toList();
		}

		if (value instanceof String) {
			return List.of(((String) value).split(" "));
		}

		return List.of();
	}
}
