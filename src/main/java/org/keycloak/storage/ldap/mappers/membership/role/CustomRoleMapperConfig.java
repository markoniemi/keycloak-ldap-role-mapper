package org.keycloak.storage.ldap.mappers.membership.role;

import org.keycloak.component.ComponentModel;

public class CustomRoleMapperConfig extends RoleMapperConfig {
  // Remove text from each role name
  public static final String REMOVE_IN_ROLE_NAME = "remove.in.role.name";
  // Add a prefix text to each role name
  public static final String ADD_ROLE_NAME_PREFIX = "add.role.name.prefix";

  public CustomRoleMapperConfig(ComponentModel mapperModel) {
    super(mapperModel);
  }

  public String getRemoveInRoleName() {
    return mapperModel.getConfig().getFirst(REMOVE_IN_ROLE_NAME);
  }

  public String getAddRoleNamePrefix() {
    return mapperModel.getConfig().getFirst(ADD_ROLE_NAME_PREFIX);
  }
}
