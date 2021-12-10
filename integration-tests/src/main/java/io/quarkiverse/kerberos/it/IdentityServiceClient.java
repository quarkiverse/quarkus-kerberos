package io.quarkiverse.kerberos.it;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

@RegisterRestClient
@Path("/")
public interface IdentityServiceClient {

    @GET
    String getIdentity();

    @GET
    String getIdentity(@HeaderParam("Authorization") String serviceTicket);
}
