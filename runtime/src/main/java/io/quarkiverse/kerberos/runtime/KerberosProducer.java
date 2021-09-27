package io.quarkiverse.kerberos.runtime;

import java.security.Principal;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.jboss.logging.Logger;

import io.quarkiverse.kerberos.KerberosPrincipal;
import io.quarkus.security.identity.SecurityIdentity;

@RequestScoped
public class KerberosProducer {
    private static final Logger LOG = Logger.getLogger(KerberosProducer.class);
    @Inject
    SecurityIdentity identity;

    @Produces
    @RequestScoped
    KerberosPrincipal currentPrincipal() {
        Principal p = identity.getPrincipal();
        if (!(p instanceof KerberosPrincipal)) {
            LOG.trace("KerberosPrincipal is not available");
            return new KerberosPrincipal();
        }
        return (KerberosPrincipal) p;
    }
}
