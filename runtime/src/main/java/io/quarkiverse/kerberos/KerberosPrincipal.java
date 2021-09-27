package io.quarkiverse.kerberos;

import java.security.Principal;

import org.ietf.jgss.GSSName;

public class KerberosPrincipal implements Principal {
    private String fullName;
    private String simpleName;
    private String realm;
    private String role;

    public KerberosPrincipal() {

    }

    public KerberosPrincipal(GSSName srcName) {
        this.fullName = srcName.toString();
        int realmIndex = fullName.lastIndexOf('@');
        if (realmIndex > 0) {
            simpleName = fullName.substring(0, realmIndex);
        } else {
            simpleName = fullName;
        }
        if (realmIndex > 0 && realmIndex + 1 < fullName.length()) {
            realm = fullName.substring(realmIndex + 1);
        }
        int roleIndex = simpleName.indexOf('/');
        if (roleIndex > 0 && roleIndex + 1 < simpleName.length()) {
            role = simpleName.substring(roleIndex + 1);
            simpleName = simpleName.substring(0, roleIndex);
        }
    }

    public String getFullName() {
        return fullName;
    }

    @Override
    public String getName() {
        return simpleName;
    }

    public String getRealm() {
        return realm;
    }

    public String getRole() {
        return role;
    }
}
