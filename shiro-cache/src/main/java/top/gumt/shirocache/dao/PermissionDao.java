package top.gumt.shirocache.credentials.top.gumt.shirocache.dao;

import top.gumt.shirocache.entity.Permission;

public interface PermissionDao {

    public Permission createPermission(Permission permission);

    public void deletePermission(Long permissionId);

}
