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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import dev.openbanking4.spring.security.multiauth.configurers.MultiAuthenticationCollectorConfigurer;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StatelessAccessTokenCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.StaticUserCollector;
import dev.openbanking4.spring.security.multiauth.configurers.collectors.X509Collector;
import dev.openbanking4.spring.security.multiauth.model.CertificateHeaderFormat;
import dev.openbanking4.spring.security.multiauth.model.authentication.X509Authentication;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;

@SpringBootApplication
@RestController
@Slf4j
public class MultiAuthSpringSecurityClientCertAndAccessToken {

	public static void main(String[] args) {
		SpringApplication.run(MultiAuthSpringSecurityClientCertAndAccessToken.class, args);
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
							 * Authentication via a certificate
							 * The username is the certificate subject.
							 * We don't expect this app to do the SSL termination, therefore we will trust the header x-cert
							 * populated by the gateway
							 */
							.collectorForAuthentication(X509Collector.x509Builder()
									.collectorName("x509-cert")
									.usernameCollector(certificatesChain -> {
										try {
											X500Name x500name = new JcaX509CertificateHolder(certificatesChain[0]).getSubject();
											RDN cn = x500name.getRDNs(BCStyle.CN)[0];
											return IETFUtils.valueToString(cn.getFirst().getValue());
										} catch (CertificateEncodingException e) {
											log.warn("Couldn't read CN from subject {}", certificatesChain[0].getSubjectDN(), e);
											return null;
										}
									})
									.collectFromHeader(CertificateHeaderFormat.PEM)
									.headerName("x-cert")
									.build()
							)

							/**
							 * Authorization via an access token
							 * The authorities are extracted from the 'scope' claim
							 */
							.collectorForAuthorzation(StatelessAccessTokenCollector.builder()
									.collectorName("stateless-access-token")
									.tokenValidator((tokenSerialised, currentAuthentication) -> {
										JWT jwt = verifyJwtSignature(tokenSerialised);
										verifyTokenBinding(jwt, currentAuthentication);
										return jwt;
									})
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

	/**
	 * Note: For simplification, the access token is signed with HMAC, using the secret
	 * 'Qt5y2isMydGwVuREoIomK9Ei70EoFQKH0GpcbtJ4'. In a real scenario, we would have called the JWK_URI of the AS
	 */
	private static JWT verifyJwtSignature(String tokenSerialised) throws ParseException, JOSEException {
		JWSObject jwsObject = JWSObject.parse(tokenSerialised);
		JWSVerifier verifier = new MACVerifier("Qt5y2isMydGwVuREoIomK9Ei70EoFQKH0GpcbtJ4");
		jwsObject.verify(verifier);
		return JWTParser.parse(tokenSerialised);
	}

	private static void verifyTokenBinding(JWT accessToken, Authentication currentAuthentication) throws ParseException {
		JSONObject cnf = accessToken.getJWTClaimsSet().getJSONObjectClaim("cnf");
		if (cnf != null) {
			// We need to verify the token binding
			String certificateThumbprint = cnf.getAsString("x5t#S256");
			if (certificateThumbprint == null) {
				throw new BadCredentialsException("Claim 'x5t#S256' is not defined but cnf present. Access token format is invalid.");
			}
			if (!(currentAuthentication instanceof X509Authentication)) {
				throw new BadCredentialsException("Request not authenticated with a client cert");
			}
			X509Authentication x509Authentication = (X509Authentication) currentAuthentication;
			String clientCertThumbprint;
			try {
				clientCertThumbprint = getThumbprint(x509Authentication.getCertificateChain()[0]);
			} catch (NoSuchAlgorithmException | CertificateEncodingException e) {
				throw new RuntimeException("Can't compute thumbprint of client certificate", e);
			}
			if (!certificateThumbprint.equals(clientCertThumbprint)) {
				throw new BadCredentialsException("The thumbprint from the client certificate '"
						+ clientCertThumbprint + "' doesn't match the one specify in the access token '" + certificateThumbprint + "'");
			}
		}
	}

	private static String getThumbprint(X509Certificate cert)
			throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		String digestHex = DatatypeConverter.printHexBinary(digest);
		return digestHex.toLowerCase();
	}
}
