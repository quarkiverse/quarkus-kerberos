package io.quarkiverse.kerberos.client;

import javax.security.auth.Subject;

public interface UserPrincipalSubjectFactory {

    Subject getSubjectForUserPrincipal(String userPrincipalName);
}
