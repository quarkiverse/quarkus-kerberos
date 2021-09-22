package io.quarkiverse.kerberos;

import javax.security.auth.Subject;

public interface ServicePrincipalSubjectFactory {

    Subject getSubjectForServicePrincipal(String servicePrincipalName);
}
