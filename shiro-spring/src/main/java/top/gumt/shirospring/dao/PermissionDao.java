package top.gumt.shirospring.dao;

import top.gumt.shirospring.entity.Permission;

public interface PermissionDao {

    public Permission createPermission(Permission permission);

    public void deletePermission(Long permissionId);

}
