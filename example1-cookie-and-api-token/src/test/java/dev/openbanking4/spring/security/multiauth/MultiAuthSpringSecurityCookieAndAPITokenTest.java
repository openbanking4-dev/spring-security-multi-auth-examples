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
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import javax.servlet.http.Cookie;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebMvcTest(MultiAuthSpringSecurityCookieAndAPIToken.class)
public class MultiAuthSpringSecurityCookieAndAPITokenTest {

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper objectMapper;

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
    public void testSendingACookie() throws Exception {
        UserDetails userDetailsExpected = User.builder()
                .username("toto")
                .password("")
                .authorities(Stream.of(new SimpleGrantedAuthority("admin"), new SimpleGrantedAuthority("clubFalafelKing")).collect(Collectors.toSet()))
                .build();

        mvc.perform(
                    get("/whoAmI")
                            .contentType(MediaType.APPLICATION_JSON)
                            .cookie(new Cookie("SSO", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbEtpbmciXX0.954F4BxnEPjeWeKlzQ_AFUwRvtT1fVg5qBjA4zOdMkQ"))
                )
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userDetailsExpected)));
    }


    @Test
    public void testAPIKey() throws Exception {
        UserDetails userDetailsExpected = User.builder()
                .username("bob")
                .password("")
                .authorities(Stream.of(new SimpleGrantedAuthority("repo-32")).collect(Collectors.toSet()))
                .build();

        mvc.perform(
                get("/whoAmI")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("key", "1NiIsInR5cCI6Ik")
        )
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(userDetailsExpected)));
    }
}
