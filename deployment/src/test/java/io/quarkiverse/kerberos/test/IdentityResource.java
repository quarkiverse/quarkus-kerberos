package io.quarkiverse.kerberos.test;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;

@Path("identity")
@Authenticated
public class IdentityResource {

    @Inject
    SecurityIdentity securityIdentity;

    @GET
    public String get() {
        return securityIdentity.getPrincipal().getName();
    }

}
