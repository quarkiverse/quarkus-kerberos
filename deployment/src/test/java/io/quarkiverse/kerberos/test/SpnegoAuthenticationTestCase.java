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

package io.quarkiverse.kerberos.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.function.Supplier;

import javax.security.auth.Subject;

import org.apache.commons.lang.ArrayUtils;
import org.hamcrest.Matchers;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.quarkiverse.kerberos.test.utils.KerberosKDCTestResource;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.QuarkusTestResource;
import io.restassured.RestAssured;

/**
 * A test case to test the SPNEGO authentication mechanism.
 */
@QuarkusTestResource(KerberosKDCTestResource.class)
public class SpnegoAuthenticationTestCase {
    public static final String NEGOTIATE = "Negotiate";

    @RegisterExtension
    static QuarkusUnitTest quarkusUnitTest = new QuarkusUnitTest()
            .setArchiveProducer(new Supplier<JavaArchive>() {
                @Override
                public JavaArchive get() {
                    return ShrinkWrap.create(JavaArchive.class)
                            .addClasses(IdentityResource.class);
                }
            });

    private static Oid SPNEGO;

    @BeforeAll
    public static void setup() throws Exception {
        SPNEGO = new Oid("1.3.6.1.5.5.2");
    }

    @Test
    public void testSpnegoSuccess() throws Exception {

        var header = RestAssured.get("/identity")
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
                                .get("/identity").then();

                        String header = result.extract().header(HttpHeaderNames.WWW_AUTHENTICATE.toString());
                        if (header != null) {

                            byte[] headerBytes = header.getBytes(StandardCharsets.US_ASCII);
                            // FlexBase64.decode() returns byte buffer, which can contain backend array of greater size.
                            // when on such ByteBuffer is called array(), it returns the underlying byte array including the 0 bytes
                            // at the end, which makes the token invalid. => using Base64 mime decoder, which returnes directly properly sized byte[].
                            token = Base64.getMimeDecoder().decode(
                                    ArrayUtils.subarray(headerBytes, NEGOTIATE.toString().length() + 1, headerBytes.length));
                        }

                        if (result.extract().statusCode() == 200) {
                            result.body(Matchers.is("jduke"));
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