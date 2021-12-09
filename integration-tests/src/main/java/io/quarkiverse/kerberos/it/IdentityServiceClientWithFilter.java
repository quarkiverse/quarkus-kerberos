package io.quarkiverse.kerberos.it;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

import org.eclipse.microprofile.rest.client.annotation.RegisterProvider;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import io.quarkiverse.kerberos.client.KerberosClientRequestFilter;

@RegisterRestClient
@RegisterProvider(KerberosClientRequestFilter.class)
@Path("/")
public interface IdentityServiceClientWithFilter {

    @GET
    String getIdentity();
}
