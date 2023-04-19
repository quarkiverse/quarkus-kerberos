package io.quarkiverse.kerberos.it;

import java.security.PrivilegedExceptionAction;
import java.util.Base64;

import javax.security.auth.Subject;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.HttpHeaders;

import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.ietf.jgss.GSSContext;

import io.quarkiverse.kerberos.client.KerberosClientSupport;

@Path("frontend")
public class FrontendResource {
    private static final String NEGOTIATE = "Negotiate";

    @Inject
    @RestClient
    IdentityServiceClientWithFilter identityServiceClientWithFilter;

    @Inject
    @RestClient
    IdentityServiceClient identityServiceClient;

    @Inject
    KerberosClientSupport kerberosClientSupport;

    @GET
    @Path("with-filter")
    public String getIdentityWithSimpleNegotiationInFilter() {
        return identityServiceClientWithFilter.getIdentity();
    }

    @GET
    @Path("with-simple-negotiation")
    public String getIdentityWithSimpleSimpleNegotiation() throws Exception {
        return identityServiceClient.getIdentity(NEGOTIATE + " " + kerberosClientSupport.getServiceTicket());
    }

    @GET
    @Path("with-multi-step-negotiation")
    public String getIdentityWithMultiStepNegotiation() throws Exception {
        return Subject.doAs(kerberosClientSupport.getUserPrincipalSubject(), new IdentityServiceAction());
    }

    @GET
    @Path("without-kerberos-support")
    public String getIdentityWithoutKerberosSupport() {
        return identityServiceClient.getIdentity();
    }

    private class IdentityServiceAction implements PrivilegedExceptionAction<String> {

        @Override
        public String run() throws Exception {
            GSSContext serviceContext = kerberosClientSupport.createServiceContext();

            byte[] tokenBytes = new byte[0];

            while (!serviceContext.isEstablished()) {
                try {
                    return identityServiceClient.getIdentity(
                            NEGOTIATE + " " + kerberosClientSupport.getNegotiateToken(serviceContext, tokenBytes));
                } catch (NotAuthorizedException ex) {
                    String header = ex.getResponse().getHeaderString(HttpHeaders.WWW_AUTHENTICATE);
                    if (header != null && header.length() > NEGOTIATE.length() + 1) {
                        tokenBytes = Base64.getDecoder().decode(header.substring(NEGOTIATE.length() + 1));
                        continue;
                    }
                    throw ex;
                }
            }
            throw new RuntimeException("Kerberos ticket can not be created");
        }
    };
}
