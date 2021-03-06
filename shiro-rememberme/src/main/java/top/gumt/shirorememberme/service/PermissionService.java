package top.gumt.shirorememberme.service;

import top.gumt.shirorememberme.entity.Permission;

public interface PermissionService {
    public Permission createPermission(Permission permission);
    public void deletePermission(Long permissionId);
}
