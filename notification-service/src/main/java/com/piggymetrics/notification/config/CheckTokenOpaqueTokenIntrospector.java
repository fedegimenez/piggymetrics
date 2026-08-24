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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
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
	private static final List<String> TIMESTAMP_CLAIMS = List.of("exp", "iat", "nbf");

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
		} catch (HttpClientErrorException.BadRequest e) {
			throw new BadOpaqueTokenException("Provided token is not active", e);
		} catch (RestClientException e) {
			throw new OAuth2IntrospectionException("Unable to introspect token", e);
		}

		if (claims == null || claims.containsKey("error") || Boolean.FALSE.equals(claims.get("active"))) {
			throw new BadOpaqueTokenException("Provided token is not active");
		}

		Map<String, Object> normalized = normalize(claims);
		return new DefaultOAuth2AuthenticatedPrincipal(principalName(normalized), normalized, authorities(normalized));
	}

	/**
	 * check_token returns the timestamp claims as epoch seconds, while the resource server casts
	 * them to {@link Instant} when it builds the authentication.
	 */
	private Map<String, Object> normalize(Map<String, Object> claims) {

		Map<String, Object> normalized = new LinkedHashMap<>(claims);

		TIMESTAMP_CLAIMS.forEach(claim -> {
			Object value = normalized.get(claim);
			if (value instanceof Number) {
				normalized.put(claim, Instant.ofEpochSecond(((Number) value).longValue()));
			}
		});

		Object audience = normalized.get("aud");
		if (audience instanceof String) {
			normalized.put("aud", List.of(audience));
		}

		return normalized;
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
