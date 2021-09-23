package io.quarkiverse.kerberos.it;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

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
