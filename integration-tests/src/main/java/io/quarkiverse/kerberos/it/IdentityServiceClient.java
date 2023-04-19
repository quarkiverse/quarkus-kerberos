package io.quarkiverse.kerberos.it;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

@RegisterRestClient
@Path("/")
public interface IdentityServiceClient {

    @GET
    String getIdentity();

    @GET
    String getIdentity(@HeaderParam("Authorization") String serviceTicket);
}
