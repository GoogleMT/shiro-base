package top.gumt.shirorealm.service;

import top.gumt.shirorealm.entity.Permission;

public interface PermissionService {
    public Permission createPermission(Permission permission);
    public void deletePermission(Long permissionId);
}
