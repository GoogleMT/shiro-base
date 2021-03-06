package top.gumt.shirorememberme.dao;


import top.gumt.shirorememberme.entity.Permission;


public interface PermissionDao {

    public Permission createPermission(Permission permission);

    public void deletePermission(Long permissionId);

}
