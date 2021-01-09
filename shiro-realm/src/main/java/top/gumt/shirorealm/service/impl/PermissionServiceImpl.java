package top.gumt.shirorealm.service.impl;

import top.gumt.shirorealm.dao.PermissionDao;
import top.gumt.shirorealm.dao.impl.PermissionDaoImpl;
import top.gumt.shirorealm.entity.Permission;
import top.gumt.shirorealm.service.PermissionService;

public class PermissionServiceImpl implements PermissionService{

    private PermissionDao permissionDao = new PermissionDaoImpl();

    public Permission createPermission(Permission permission) {
        return permissionDao.createPermission(permission);
    }

    public void deletePermission(Long permissionId) {
        permissionDao.deletePermission(permissionId);
    }
}
