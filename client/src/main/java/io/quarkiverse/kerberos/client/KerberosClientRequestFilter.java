package io.quarkiverse.kerberos.client;

import java.io.IOException;

import javax.inject.Inject;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;

public class KerberosClientRequestFilter implements ClientRequestFilter {

    private static final String AUTHORIZATION = "Authorization";
    private static final String NEGOTIATE = "Negotiate";

    @Inject
    KerberosClientSupport kerberosClientSupport;

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        String serviceTicket = kerberosClientSupport.getServiceTicket();
        requestContext.getHeaders().add(AUTHORIZATION, NEGOTIATE + " " + serviceTicket);
    }

}
