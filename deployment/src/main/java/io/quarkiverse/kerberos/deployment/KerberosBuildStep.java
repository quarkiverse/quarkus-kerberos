package io.quarkiverse.kerberos.deployment;

import io.quarkiverse.kerberos.runtime.KerberosAuthenticationMechanism;
import io.quarkiverse.kerberos.runtime.KerberosIdentityProvider;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;

public class KerberosBuildStep {

    @BuildStep
    public FeatureBuildItem featureBuildItem() {
        return new FeatureBuildItem("kerberos");
    }

    @BuildStep
    public AdditionalBeanBuildItem additionalBeans() {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder().setUnremovable()
                .addBeanClass(KerberosAuthenticationMechanism.class)
                .addBeanClass(KerberosIdentityProvider.class);
        return builder.build();
    }
}
