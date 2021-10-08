package io.quarkiverse.kerberos.test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.quarkiverse.kerberos.test.utils.KerberosTestClient;
import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;

public class SpnegoAuthenticationDevModeTestCase {
    public static final String NEGOTIATE = "Negotiate";

    private static Class<?>[] testClasses = {
            IdentityResource.class
    };

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addClasses(testClasses)
                    .addAsResource("application-dev-mode.properties", "application.properties"));

    KerberosTestClient kerberosTestClient = new KerberosTestClient();

    @Test
    public void testSpnegoSuccess() throws Exception {

        var header = RestAssured.get("/identity")
                .then().statusCode(401)
                .extract()
                .header(HttpHeaderNames.WWW_AUTHENTICATE.toString());
        assertEquals(NEGOTIATE, header);

        var result = kerberosTestClient.get("/identity", "alice", "alice");
        result.statusCode(401);

        test.modifyResourceFile("application.properties", s -> s.replace("QUARKUSDEV.IO", "QUARKUS.IO"));

        result = kerberosTestClient.get("/identity", "alice", "alice");
        result.statusCode(200).body(Matchers.is("alice"));
    }
}
