/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.quarkiverse.kerberos.it;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.PrivilegedExceptionAction;
import java.util.Base64;

import javax.security.auth.Subject;

import org.hamcrest.Matchers;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.quarkiverse.kerberos.test.utils.KerberosKDCTestResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.common.http.TestHTTPEndpoint;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;

/**
 * A test case to test the SPNEGO authentication mechanism.
 */
@QuarkusTest
@TestHTTPEndpoint(IdentityResource.class)
@QuarkusTestResource(KerberosKDCTestResource.class)
public class KerberosResourceTestCase {
    public static final String NEGOTIATE = "Negotiate";

    private static Oid SPNEGO;

    @BeforeAll
    public static void startServers() throws Exception {
        SPNEGO = new Oid("1.3.6.1.5.5.2");
    }

    @Test
    public void testSpnegoSuccess() throws Exception {

        var header = RestAssured.get()
                .then().statusCode(401)
                .extract()
                .header(HttpHeaderNames.WWW_AUTHENTICATE.toString());
        assertEquals(NEGOTIATE, header);

        Subject clientSubject = KerberosKDCTestResource.login("jduke", "theduke".toCharArray());

        Subject.doAs(clientSubject, new PrivilegedExceptionAction<Void>() {

            @Override
            public Void run() throws Exception {
                GSSManager gssManager = GSSManager.getInstance();
                GSSName serverName = gssManager.createName("HTTP/localhost", null);

                GSSContext context = gssManager.createContext(serverName, SPNEGO, null, GSSContext.DEFAULT_LIFETIME);

                byte[] token = new byte[0];

                boolean gotOur200 = false;
                while (!context.isEstablished()) {
                    token = context.initSecContext(token, 0, token.length);

                    if (token != null && token.length > 0) {
                        var result = RestAssured.given()
                                .header(HttpHeaderNames.AUTHORIZATION.toString(),
                                        NEGOTIATE + " " + Base64.getEncoder().encodeToString(token))
                                .get().then();

                        String header = result.extract().header(HttpHeaderNames.WWW_AUTHENTICATE.toString());
                        if (header != null) {
                            token = Base64.getDecoder().decode(header.substring(NEGOTIATE.length() + 1));
                        }

                        if (result.extract().statusCode() == 200) {
                            result.body(Matchers.is("jduke jduke@QUARKUS.IO QUARKUS.IO"));
                            gotOur200 = true;
                        } else if (result.extract().statusCode() == 401) {
                            assertTrue(header != null, "We did get a header.");
                        } else {
                            fail(String.format("Unexpected status code %d", result.extract().statusCode()));
                        }
                    }
                }

                assertTrue(gotOur200);
                assertTrue(context.isEstablished());
                return null;
            }
        });
    }

}
