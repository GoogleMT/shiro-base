package top.gumt.shirobase;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.junit.platform.engine.support.hierarchical.ThrowableCollector;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.File;

@SpringBootTest
class ShiroBaseApplicationTests {


    @Test
    void contextLoads() {
        // 获取SecurityManager工厂, 此处使用ini配置文件初始化SecurityManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-authenticator-all-success.ini");
        // 2.得到SecurityManager实例, 绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        // 3.得到Subject 及创建用户名/密码身份验证Token(即用身份/凭证)
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        try {
            // 4.登录, 即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            // 5. 身份验证失败
            e.printStackTrace();
        }
        Assert.assertEquals(true, subject.isAuthenticated()); //断言用户已经登录
        // 6.退出
        subject.login(token);
    }

    private void login(String configFile) {
        //1、获取SecurityManager工厂，此处使用 Ini配置文件初始化SecurityManager

        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory(configFile);
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        //3、得到Subject 及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        subject.login(token);
    }

    @Test
    void test() {
        login("classpath:shiro-authenticator-all-success.ini");
        Subject subject = SecurityUtils.getSubject();
        //得到一个身份集合，其包含了 Realm验证成功的身份信息
        PrincipalCollection principalCollection = subject.getPrincipals();
        System.out.println(principalCollection);
        Assert.assertEquals(2, principalCollection.asList().size());
    }

}
