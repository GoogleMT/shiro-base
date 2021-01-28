package top.gumt.shirospring.service;

import top.gumt.shirospring.entity.Permission;

public interface PermissionService {
    public Permission createPermission(Permission permission);
    public void deletePermission(Long permissionId);
}
