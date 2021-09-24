package io.quarkiverse.kerberos;

import java.security.Principal;

import org.ietf.jgss.GSSName;

public class KerberosPrincipal implements Principal {
    private final String simpleName;
    private final String fullName;
    private final String realmName;

    public KerberosPrincipal(GSSName srcName) {
        this.fullName = srcName.toString();
        int realmIndex = fullName.lastIndexOf('@');
        if (realmIndex > 0) {
            simpleName = fullName.substring(0, realmIndex);
        } else {
            simpleName = fullName;
        }
        if (realmIndex > 0 && realmIndex + 1 < fullName.length()) {
            realmName = fullName.substring(realmIndex + 1);
        } else {
            realmName = null;
        }
    }

    public String getFullName() {
        return fullName;
    }

    @Override
    public String getName() {
        return simpleName;
    }

    public String getRealmName() {
        return realmName;
    }
}
