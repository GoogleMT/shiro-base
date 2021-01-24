package top.gumt.shirocache.service;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
import top.gumt.shirocache.entity.User;

/**
 * 密码加密工具类
 */
public class PasswordHelper {

    private RandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();

    private String algorithmName = "md5";
    private final int hashIterations = 2;

    public void encryptPassword(User user) {

        user.setSalt(randomNumberGenerator.nextBytes().toHex());

        String newPassword = new SimpleHash(
                algorithmName,   // 加密算法  这里使用的MD5
                user.getPassword(), // 密码
                ByteSource.Util.bytes(user.getCredentialsSalt()), // 盐 username + salt
                hashIterations //迭代密码次数
        ).toHex();

        user.setPassword(newPassword);
    }
}
