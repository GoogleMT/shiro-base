package top.gumt.shirocache.service;

import top.gumt.shirocache.entity.Permission;

public interface PermissionService {
    public Permission createPermission(Permission permission);
    public void deletePermission(Long permissionId);
}
