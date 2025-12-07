package org.keycloak.storage.ldap.mappers.membership.role;

import org.keycloak.component.ComponentModel;

public class CustomRoleMapperConfig extends RoleMapperConfig {
  // Search&replace text in role name
  public static final String FIND_IN_ROLE_NAME = "find.in.role.name";
  public static final String REPLACE_IN_ROLE_NAME = "replace.in.role.name";

  public CustomRoleMapperConfig(ComponentModel mapperModel) {
    super(mapperModel);
  }

  public String getFindInRoleName() {
    return mapperModel.getConfig().getFirst(FIND_IN_ROLE_NAME);
  }

  public String getReplaceInRoleName() {
    return mapperModel.getConfig().getFirst(REPLACE_IN_ROLE_NAME);
  }
}
