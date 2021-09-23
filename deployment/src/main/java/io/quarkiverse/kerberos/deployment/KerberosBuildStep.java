package io.quarkiverse.kerberos.deployment;

import com.sun.security.auth.module.Krb5LoginModule;

import io.quarkiverse.kerberos.runtime.KerberosAuthenticationMechanism;
import io.quarkiverse.kerberos.runtime.KerberosIdentityProvider;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBundleBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;

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

    @BuildStep
    public ReflectiveClassBuildItem reflection() {
        return ReflectiveClassBuildItem.builder(Krb5LoginModule.class).build();
    }

    @BuildStep
    public NativeImageResourceBundleBuildItem resourceBundleBuildItem() {
        return new NativeImageResourceBundleBuildItem("sun.security.util.AuthResources");
    }
}
