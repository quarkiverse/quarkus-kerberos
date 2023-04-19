package io.quarkiverse.kerberos.it;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import io.quarkiverse.kerberos.KerberosPrincipal;
import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;

@Path("identity")
@Authenticated
public class IdentityResource {

    @Inject
    SecurityIdentity securityIdentity;

    @Inject
    KerberosPrincipal kerberosPrincipal;

    @GET
    public String getIdentity() {
        return securityIdentity.getPrincipal().getName() + " " + kerberosPrincipal.getFullName() + " "
                + kerberosPrincipal.getRealm();
    }

}
