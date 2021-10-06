package io.quarkiverse.kerberos.test.utils;

import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;

import javax.security.auth.Subject;

import org.apache.commons.lang.ArrayUtils;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;

public class KerberosTestClient {
    public static final String NEGOTIATE = "Negotiate";

    public ValidatableResponse get(String principalName, String principalPassword) {
        return get("/", principalName, principalPassword);
    }

    public ValidatableResponse get(String path, String principalName, String principalPassword) {
        try {
            Subject clientSubject = KerberosKDCTestResource.login(principalName, principalPassword.toCharArray());

            return Subject.doAs(clientSubject, new PrivilegedExceptionAction<ValidatableResponse>() {

                @Override
                public ValidatableResponse run() throws Exception {
                    GSSManager gssManager = GSSManager.getInstance();
                    GSSName serverName = gssManager.createName("HTTP/localhost", null);

                    GSSContext context = gssManager.createContext(serverName, createSpnegoOid(), null,
                            GSSContext.DEFAULT_LIFETIME);

                    byte[] token = new byte[0];

                    while (!context.isEstablished()) {
                        token = context.initSecContext(token, 0, token.length);

                        if (token != null && token.length > 0) {
                            ValidatableResponse result = RestAssured.given()
                                    .header(HttpHeaderNames.AUTHORIZATION.toString(),
                                            NEGOTIATE + " " + Base64.getEncoder().encodeToString(token))
                                    .get(path).then();

                            if (result.extract().statusCode() == 200) {
                                return result;
                            } else if (result.extract().statusCode() == 401) {
                                String header = result.extract().header(HttpHeaderNames.WWW_AUTHENTICATE.toString());
                                if (header != null) {
                                    if (header.length() > NEGOTIATE.toString().length() + 1) {
                                        // Negotiation continues

                                        byte[] headerBytes = header.getBytes(StandardCharsets.US_ASCII);
                                        // FlexBase64.decode() returns byte buffer, which can contain backend array of greater size.
                                        // when on such ByteBuffer is called array(), it returns the underlying byte array including the 0 bytes
                                        // at the end, which makes the token invalid. => using Base64 mime decoder, which returnes directly properly sized byte[].
                                        token = Base64.getMimeDecoder().decode(
                                                ArrayUtils.subarray(headerBytes, NEGOTIATE.toString().length() + 1,
                                                        headerBytes.length));
                                    } else {
                                        fail("Negotiation data has not been returned with WWW-Authenticate");
                                    }
                                } else {
                                    //No challenge, authentication failure
                                    return result;
                                }
                            } else {
                                fail(String.format("Unexpected status code %d", result.extract().statusCode()));
                            }
                        }
                    }
                    fail("Negotiation failure");
                    return null;
                }
            });
        } catch (Exception ex) {
            fail(String.format("Unexpected exception: ", ex.getMessage()));
        }
        return null;
    }

    private Oid createSpnegoOid() {
        try {
            return new Oid("1.3.6.1.5.5.2");
        } catch (GSSException ex) {
            throw new RuntimeException(ex);
        }
    }
}
