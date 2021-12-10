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

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;

/**
 * A test case to test the SPNEGO authentication mechanism.
 */
@QuarkusTest
public class KerberosClientTestCase {

    @Test
    public void testSpnegoSuccessWithSimpleNegotiation() throws Exception {

        RestAssured.get("/frontend/with-simple-negotiation")
                .then().statusCode(200)
                .body(Matchers.is("jduke jduke@QUARKUS.IO QUARKUS.IO"));
    }

    @Test
    public void testSpnegoSuccessWithMultiStepNegotiation() throws Exception {

        RestAssured.get("/frontend/with-multi-step-negotiation")
                .then().statusCode(200)
                .body(Matchers.is("jduke jduke@QUARKUS.IO QUARKUS.IO"));
    }

    @Test
    public void testSpnegoSuccessWithFilter() throws Exception {

        RestAssured.get("/frontend/with-filter")
                .then().statusCode(200)
                .body(Matchers.is("jduke jduke@QUARKUS.IO QUARKUS.IO"));
    }

    @Test
    public void testSpnegoFailure() throws Exception {

        RestAssured.get("/frontend/without-kerberos-support")
                .then().statusCode(401);
    }

}
