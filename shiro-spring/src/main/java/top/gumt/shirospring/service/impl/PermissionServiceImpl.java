package top.gumt.shirospring.service.impl;

import top.gumt.shirospring.dao.PermissionDao;
import top.gumt.shirospring.entity.Permission;
import top.gumt.shirospring.service.PermissionService;

public class PermissionServiceImpl implements PermissionService {

    private PermissionDao permissionDao;

    public void setPermissionDao(PermissionDao permissionDao) {
        this.permissionDao = permissionDao;
    }

    public Permission createPermission(Permission permission) {
        return permissionDao.createPermission(permission);
    }

    public void deletePermission(Long permissionId) {
        permissionDao.deletePermission(permissionId);
    }
}
