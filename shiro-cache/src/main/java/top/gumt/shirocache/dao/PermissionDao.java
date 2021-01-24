package top.gumt.shirocache.credentials.top.gumt.shirocache.dao;

import top.gumt.shirocache.entity.Permission;

public interface PermissionDao {
    /**
     * 给权限表中添加数据
     * @param permission
     * @return
     */
    public Permission createPermission(Permission permission);

    /**
     * 删除权限表中的数据
     * @param permissionId
     */
    public void deletePermission(Long permissionId);

}
