package org.keycloak.storage.ldap.mappers.membership.role;

import java.util.List;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.LDAPStorageMapperFactory;

import com.google.auto.service.AutoService;

@AutoService(LDAPStorageMapperFactory.class)
public class CustomRoleLDAPStorageMapperFactory extends RoleLDAPStorageMapperFactory {
  public static final String PROVIDER_ID = "custom-role-ldap-mapper";

  @Override
  public List<ProviderConfigProperty> getConfigProperties(RealmModel realm, ComponentModel parent) {
    super.configProperties.addAll(
        ProviderConfigurationBuilder.create()
            .property()
            .name(CustomRoleMapperConfig.FIND_IN_ROLE_NAME)
            .label("Find text in role")
            .helpText("Text to replace in role")
            .type(ProviderConfigProperty.STRING_TYPE)
            .add()
            .property()
            .name(CustomRoleMapperConfig.REPLACE_IN_ROLE_NAME)
            .label("Replace with text")
            .helpText("Replace found text with string")
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
