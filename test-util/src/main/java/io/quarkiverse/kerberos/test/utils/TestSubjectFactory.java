package io.quarkiverse.kerberos.test.utils;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkiverse.kerberos.ServicePrincipalSubjectFactory;

@ApplicationScoped
public class TestSubjectFactory implements ServicePrincipalSubjectFactory {

    @Override
    public Subject getSubjectForServicePrincipal(String servicePrincipalName) {
        try {
            return KerberosKDCTestResource.login(servicePrincipalName, "servicepwd".toCharArray());
        } catch (LoginException e) {
            throw new RuntimeException(e);
        }
    }

}
