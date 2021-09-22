package io.quarkiverse.kerberos;

import io.quarkus.security.identity.request.BaseAuthenticationRequest;

public class NegotiateAuthenticationRequest extends BaseAuthenticationRequest {

    private final String value;

    public NegotiateAuthenticationRequest(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
