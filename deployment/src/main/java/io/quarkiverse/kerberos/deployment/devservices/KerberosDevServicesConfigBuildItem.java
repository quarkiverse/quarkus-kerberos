package io.quarkiverse.kerberos.deployment.devservices;

import java.util.Map;

import io.quarkus.builder.item.SimpleBuildItem;

public final class KerberosDevServicesConfigBuildItem extends SimpleBuildItem {

    private final Map<String, Object> properties;

    public KerberosDevServicesConfigBuildItem(Map<String, Object> configProperties) {
        this.properties = configProperties;
    }

    public Map<String, Object> getProperties() {
        return properties;
    }
}
