package top.gumt.shirocache.service.impl;

import top.gumt.shirocache.dao.impl.PermissionDaoImpl;
import top.gumt.shirocache.entity.Permission;
import top.gumt.shirocache.service.PermissionService;

public class PermissionServiceImpl implements PermissionService {

    private top.gumt.shirocache.credentials.top.gumt.shirocache.dao.PermissionDao permissionDao = new PermissionDaoImpl();

    public Permission createPermission(Permission permission) {
        return permissionDao.createPermission(permission);
    }

    public void deletePermission(Long permissionId) {
        permissionDao.deletePermission(permissionId);
    }
}
