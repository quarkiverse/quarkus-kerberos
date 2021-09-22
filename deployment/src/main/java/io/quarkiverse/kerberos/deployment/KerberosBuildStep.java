package io.quarkiverse.kerberos.deployment;

import io.quarkiverse.kerberos.runtime.KerberosAuthenticationMechanism;
import io.quarkiverse.kerberos.runtime.KerberosIdentityProvider;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;

public class KerberosBuildStep {

    @BuildStep
    public FeatureBuildItem featureBuildItem() {
        return new FeatureBuildItem("kerberos");
    }

    @BuildStep
    public void additionalBeans(BuildProducer<AdditionalBeanBuildItem> additionalBeans,
            BuildProducer<ReflectiveClassBuildItem> reflectiveClasses) {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder().setUnremovable();

        builder.addBeanClass(KerberosAuthenticationMechanism.class)
                .addBeanClass(KerberosIdentityProvider.class);
        additionalBeans.produce(builder.build());
    }
}
