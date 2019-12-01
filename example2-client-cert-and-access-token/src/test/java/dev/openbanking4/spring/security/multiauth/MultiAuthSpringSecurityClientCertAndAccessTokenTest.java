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

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.openbanking4.spring.security.multiauth.model.granttypes.ScopeGrantType;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(MultiAuthSpringSecurityClientCertAndAccessToken.class)
public class MultiAuthSpringSecurityClientCertAndAccessTokenTest {

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper objectMapper;


    private String testPSD2Certificate =  "-----BEGIN CERTIFICATE-----\n" +
            "MIIDvzCCAqegAwIBAgIEcBt91TANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMC\n" +
            "R0IxDTALBgNVBAgTBEF2b24xEDAOBgNVBAcTB0JyaXN0b2wxGTAXBgNVBAoTEE9w\n" +
            "ZW5CYW5raW5nNC5kZXYxKzApBgNVBAsTIlNwcmluZy1zZWN1cml0eS1tdWx0aS1h\n" +
            "dXRoLWV4YW1wbGUxDjAMBgNVBAMTBWFsaWNlMB4XDTE5MTIwMTE1NTIxM1oXDTIy\n" +
            "MDMwNTE1NTIxM1owgYYxCzAJBgNVBAYTAkdCMQ0wCwYDVQQIEwRBdm9uMRAwDgYD\n" +
            "VQQHEwdCcmlzdG9sMRkwFwYDVQQKExBPcGVuQmFua2luZzQuZGV2MSswKQYDVQQL\n" +
            "EyJTcHJpbmctc2VjdXJpdHktbXVsdGktYXV0aC1leGFtcGxlMQ4wDAYDVQQDEwVh\n" +
            "bGljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZ/4eeNOvY8PFkr\n" +
            "2LgrAB9pU0W3MtPXBuOpsKtPLpByWwxN8Ki5fRktzpCxMDtT7QJ9A0TrWuZ2J5R0\n" +
            "44iILfRLz+SfcClnimM5nH3iSd4DiBt5ve/VwdlNqzoqf/xCCBC4i4ygES9LLr9G\n" +
            "Ia+04Bkij6lFjqnKLumXg1U+g/TZnUVOlTu7HTYEBaFtHJCl44bk2zPGCsdkbKGy\n" +
            "u08txPv50aCcgwb0VMA+IHY5KF2xbXh4UeOq7gRJkGTZNPJft3Ow8ROWz0VdvdGu\n" +
            "anznaamUxiAawQrujRxUXgQUQlC2EpAruknsP9Hg5198BA1sgpMn9Jwgg1TOLuuW\n" +
            "lYjeptkCAwEAAaMzMDEwHQYDVR0OBBYEFEgjYMV2dhr9Tn/U9zjvxGh7gNuPMBAG\n" +
            "A1UdEQQJMAeCBWFsaWNlMA0GCSqGSIb3DQEBCwUAA4IBAQAjrLOmdYV0bJgYVx8A\n" +
            "n/wXl2+1Skq7rrqAufxYJRW2cSa6RiY11S+QOIEPC052bQdZo26BSUAPxxfVeNR0\n" +
            "GPoIFl1BECdE/GHZdKtkfOqAvBJqSyNuVRdYC6ePhrEI/9Q3zIW2LDqhRfJuPgdV\n" +
            "znCG3xw+LgZeb4Y1+7Lvd6PGxJOsdvP1mRInoH36fI+A/+lRfTsdb35QuRYX8Xdk\n" +
            "VnFs9ugu9adXM4W5NHbQZXzeM76MARfusezpdF011dFX3C45jArRUwjXwt/w8G7/\n" +
            "ps1KMmHkhQ1MzxLRAiqtTWkWqnwxUMI8vxgLpyLLZNFMuJPESuhs3QOjqAj0A31v\n" +
            "SiCd\n" +
            "-----END CERTIFICATE-----\n";

    @Test
    public void testSendingNoCredential() throws Exception {
        UserDetails userDetailsExpected = User.builder()
                .username("anonymous")
                .password("")
                .authorities(Collections.EMPTY_SET)
                .build();

        mvc.perform(get("/whoAmI").contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userDetailsExpected)));
    }

    @Test
    public void testSendingAccessTokenAndCert() throws Exception {
        UserDetails userDetailsExpected = User.builder()
                .username("alice")
                .password("")
                .authorities(Stream.of( new ScopeGrantType("accounts"), new ScopeGrantType("payments")).collect(Collectors.toSet()))
                .build();

        mvc.perform(
                get("/whoAmI")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("x-cert", testPSD2Certificate)
                        .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl0sImNuZiI6eyJ4NXQjUzI1NiI6ImMxYzRmMDUwZjFlMWJlZGVjOTg3Y2ViNGFiOThlMmM4M2U2NjUzZjUifX0.-4pfNjqXdkTcpiRieH09HIOMmE3mJF6zlksfocyXXAA")
        )
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userDetailsExpected)));
    }
}
