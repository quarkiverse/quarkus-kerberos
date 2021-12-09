package io.quarkiverse.kerberos.it;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

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
