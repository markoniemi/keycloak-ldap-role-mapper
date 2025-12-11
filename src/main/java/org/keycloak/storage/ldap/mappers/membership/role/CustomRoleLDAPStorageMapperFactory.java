package org.keycloak.storage.ldap.mappers.membership.role;

import com.google.auto.service.AutoService;
import java.util.List;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapperFactory;

@AutoService(LDAPStorageMapperFactory.class)
public class CustomRoleLDAPStorageMapperFactory extends RoleLDAPStorageMapperFactory {
  public static final String PROVIDER_ID = "custom-ldap-role-mapper";

  @Override
  public List<ProviderConfigProperty> getConfigProperties(RealmModel realm, ComponentModel parent) {
    configProperties.clear();
    configProperties.addAll(super.getConfigProperties(realm, parent));
    configProperties.addAll(
        ProviderConfigurationBuilder.create()
            .property()
            .name(CustomRoleMapperConfig.REMOVE_IN_ROLE_NAME)
            .label("Remove in role name")
            .helpText("Text to remove in each role name")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(CustomRoleMapperConfig.ADD_ROLE_NAME_PREFIX)
            .label("Add role name prefix")
            .helpText("Add a prefix to each role name")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .build());
    return configProperties;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  protected AbstractLDAPStorageMapper createMapper(
      ComponentModel mapperModel, LDAPStorageProvider federationProvider) {
    return new CustomRoleLDAPStorageMapper(mapperModel, federationProvider, this);
  }
}
