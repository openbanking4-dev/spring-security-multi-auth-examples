/**
 * Copyright 2019 Quentin Castel.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package dev.openbanking4.spring.security.multiauth;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTParser;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.APIKeyCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.CustomJwtCookieCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StaticUserCollector;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
@RestController
public class MultiAuthSpringSecurityCookieAndAPIToken {

	public static void main(String[] args) {
		SpringApplication.run(MultiAuthSpringSecurityCookieAndAPIToken.class, args);
	}

	/**
	 * A Rest endpoint that returns the identity and authorisation of the user
	 * @param principal injected by Spring security, this is what we are interested to visualise
	 * @return the principal in JSON
	 */
	@GetMapping("/whoAmI")
	public Object whoAmI(Principal principal) {
		return ((Authentication) principal).getPrincipal();
	}


	@Configuration
	static class MultiAuthWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
				.anyRequest()
				.permitAll()
				.and()
				.apply(new MultiAuthenticationCollectorConfigurer<HttpSecurity>()
					/**
					 * Authentication & authorisation via a cookie 'SSO'
					 * The authorities are extracted from the 'group' claim
					 * The username is extracted from the 'sub' claim
					 * Note: JWT cookies expected to be signed with HMAC with "Qt5y2isMydGwVuREoIomK9Ei70EoFQKH0GpcbtJ4" as a secret
					 */
					.collector(CustomJwtCookieCollector.builder()
							.collectorName("Cookie-SSO")
							.authoritiesCollector(token -> token.getJWTClaimsSet().getStringListClaim("group").stream()
									.map(g -> new SimpleGrantedAuthority(g)).collect(Collectors.toSet()))
							.tokenValidator(tokenSerialised -> {
								JWSObject jwsObject = JWSObject.parse(tokenSerialised);
								JWSVerifier verifier = new MACVerifier("Qt5y2isMydGwVuREoIomK9Ei70EoFQKH0GpcbtJ4");
								jwsObject.verify(verifier);
								return JWTParser.parse(tokenSerialised);
							})
							.cookieName("SSO")
							.build()
					)

					/**
					 * Authentication via an API key
					 * The username and authorities are extracted by calling your API key service
					 */
					.collector(APIKeyCollector.<User>builder()
							.collectorName("API-Key")
							.apiKeyExtractor(req -> req.getHeader("key"))
							.apiKeyValidator(apiKey -> {
								//Here call the API key validator service. We will mock the response and build the
								//user manually
								return new User("bob", "",
										Stream.of(new SimpleGrantedAuthority("repo-42")).collect(Collectors.toSet()));
							})
							.usernameCollector(User::getUsername)
							.authoritiesCollector(user -> new HashSet<>(user.getAuthorities()))
							.build()
					)

					/**
					 * Static authentication
					 * If no authentication was possible with the previous collector, we default to the anonymous user
					 */
					.collectorForAuthentication(StaticUserCollector.builder()
							.collectorName("StaticUser-anonymous")
							.usernameCollector(() -> "anonymous")
							.build())
				)
			;
		}
	}
}
