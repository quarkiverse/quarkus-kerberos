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

import java.util.function.Supplier;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.quarkiverse.kerberos.test.utils.KerberosTestClient;
import io.quarkus.test.QuarkusUnitTest;
import io.restassured.RestAssured;

/**
 * A test case to test the SPNEGO authentication mechanism.
 */
public class SpnegoAuthenticationTestCase {
    public static final String NEGOTIATE = "Negotiate";

    @RegisterExtension
    static QuarkusUnitTest quarkusUnitTest = new QuarkusUnitTest()
            .setArchiveProducer(new Supplier<JavaArchive>() {
                @Override
                public JavaArchive get() {
                    return ShrinkWrap.create(JavaArchive.class)
                            .addClasses(IdentityResource.class)
                            .addAsResource("application.properties");
                }
            });

    KerberosTestClient kerberosTestClient = new KerberosTestClient();

    @Test
    public void testSpnegoSuccess() throws Exception {

        var header = RestAssured.get("/identity")
                .then().statusCode(401)
                .extract()
                .header(HttpHeaderNames.WWW_AUTHENTICATE.toString());
        assertEquals(NEGOTIATE, header);

        var result = kerberosTestClient.get("/identity", "jduke", "theduke");
        result.statusCode(200).body(Matchers.is("jduke"));
    }

}
