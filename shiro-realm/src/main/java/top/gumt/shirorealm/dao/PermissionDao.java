package top.gumt.shirorealm.dao;

import top.gumt.shirorealm.entity.Permission;

public interface PermissionDao {
    public Permission createPermission(Permission permission);

    public void deletePermission(Long permissionId);
}
