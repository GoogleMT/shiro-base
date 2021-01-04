package top.gumt.shirobase;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.commons.beanutils.BeanUtilsBean;
import org.apache.commons.beanutils.converters.AbstractConverter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.WildcardPermissionResolver;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.codec.Hex;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.crypto.BlowfishCipherService;
import org.apache.shiro.crypto.DefaultBlockCipherService;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.*;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.SimpleByteSource;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.junit.platform.engine.support.hierarchical.ThrowableCollector;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.File;
import java.security.Key;
import java.util.Arrays;

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

    private void login(String configFile, String username, String password) {
        //1、获取SecurityManager工厂，此处使用 Ini配置文件初始化SecurityManager

        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory(configFile);
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        //3、得到Subject 及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
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

    @Test
    public void testHasRole() {
        login("classpath:shiro-role.ini", "zhang", "123");
        // 判断拥有角色 role1
        Subject subject = SecurityUtils.getSubject();
        Assert.assertTrue(subject.hasRole("role1"));
        // 判断拥有角色 role1, role2, role3
        Assert.assertTrue(subject.hasAllRoles(Arrays.asList("role1", "role2")));
        // 判断拥有角色 role1 and role2 and !role3
        boolean[] result = subject.hasRoles(Arrays.asList("role1", "role2", "role3"));
        Assert.assertEquals(true, result[0]);
        Assert.assertEquals(true, result[1]);
        Assert.assertEquals(true, result[2]);
    }

    @Test
    public void testIsPermitted() {
        login("classpath:shiro-permission.ini", "zhang", "123");
        //判断拥有权限：user:create
        Subject subject = SecurityUtils.getSubject();
        Assert.assertTrue(subject.isPermitted("user:create"));
        //判断拥有权限：user:update and user:delete
        Assert.assertTrue(subject.isPermittedAll("user:update", "user:delete"));
        //判断没有权限：user:view
        Assert.assertFalse(subject.isPermitted("user:view"));
    }

    @Test
    public void testIsPermitted01() {
        login("classpath:shiro-authorizer.ini", "zhang", "123");
        //判断拥有权限：user:create
        Subject subject = SecurityUtils.getSubject();
        Assert.assertTrue(subject.isPermitted("user1:update"));
        Assert.assertTrue(subject.isPermitted("user2:update"));
        //通过二进制位的方式表示权限
        Assert.assertTrue(subject.isPermitted("+user1+2"));//新增权限
        Assert.assertTrue(subject.isPermitted("+user1+8"));//查看权限
        Assert.assertTrue(subject.isPermitted("+user2+10"));//新增及查看
        Assert.assertFalse(subject.isPermitted("+user1+4"));//没有删除权限
        Assert.assertTrue(subject.isPermitted("menu:view"));//通过MyRolePermissionResolver解析得到的权限
    }

    /**
     * 通过纯Java代码的形式构造SecurityManager
     */
    @Test
    public void nonConfigurationCreateTest() {
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        // 设置authenticatior
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        authenticator.setAuthenticationStrategy(new AtLeastOneSuccessfulStrategy());
        securityManager.setAuthenticator(authenticator);
        // 设置authorizer
        ModularRealmAuthorizer authorizer = new ModularRealmAuthorizer();
        authorizer.setPermissionResolver(new WildcardPermissionResolver());
        securityManager.setAuthenticator(authenticator);
        // 设置Realm
        DruidDataSource druidDataSource = new DruidDataSource();
        druidDataSource.setDriverClassName("com.mysql.jdbc.Driver");
        druidDataSource.setUrl("jdbc:mysql://localhost:3306/shiro");
        druidDataSource.setUsername("root");
        druidDataSource.setPassword("root");
        JdbcRealm jdbcRealm = new JdbcRealm();
        jdbcRealm.setDataSource(druidDataSource);
        jdbcRealm.setPermissionsLookupEnabled(true);
        securityManager.setRealms(Arrays.asList((Realm) jdbcRealm));
        // 将SecurityManager 设置到 SecurityUtils 方便全局管理
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        subject.login(token);
        Assert.assertTrue(subject.isAuthenticated());
    }

    /**
     * 通过配置文件的形式构造SecurityManager
     */
    @Test
    public void configurationCreateTest() {
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-config.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);;
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        subject.login(token);
        Assert.assertTrue(subject.isAuthenticated());
    }

    @Test
    public void testBase64() {
        String str = "hello";
        String base64Encoded = Base64.encodeToString(str.getBytes());
        String str2 = Base64.decodeToString(base64Encoded);
        Assert.assertEquals(str, str2);

    }

    @Test
    public void testHex() {
        String str = "hello";
        String base64Encoded = Hex.encodeToString(str.getBytes());
        String str2 = new String(Hex.decode(base64Encoded.getBytes()));
        Assert.assertEquals(str, str2);

    }

    @Test
    public void testCodecSupport() {
        String str = "hello";
        byte[] bytes = CodecSupport.toBytes(str, "utf-8");
        String str2 = CodecSupport.toString(bytes, "utf-8");
        Assert.assertEquals(str, str2);
    }


    @Test
    public void testRandom() {
        //生成随机数
        SecureRandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();
        randomNumberGenerator.setSeed("123".getBytes());
        System.out.println(randomNumberGenerator.nextBytes().toHex());
    }



    @Test
    public void testMd5() {
        String str = "hello";
        String salt = "123";
        String md5 = new Md5Hash(str, salt).toString();//还可以转换为 toBase64()/toHex()
        System.out.println(md5);


    }

    @Test
    public void testSha1() {
        String str = "hello";
        String salt = "123";
        String sha1 = new Sha1Hash(str, salt).toString();
        System.out.println(sha1);

    }

    @Test
    public void testSha256() {
        String str = "hello";
        String salt = "123";
        String sha1 = new Sha256Hash(str, salt).toString();
        System.out.println(sha1);

    }

    @Test
    public void testSha384() {
        String str = "hello";
        String salt = "123";
        String sha1 = new Sha384Hash(str, salt).toString();
        System.out.println(sha1);

    }

    @Test
    public void testSha512() {
        String str = "hello";
        String salt = "123";
        String sha1 = new Sha512Hash(str, salt).toString();
        System.out.println(sha1);

    }

    @Test
    public void testSimpleHash() {
        String str = "hello";
        String salt = "123";
        //MessageDigest
        String simpleHash = new SimpleHash("SHA-1", str, salt).toString();
        System.out.println(simpleHash);

    }



    @Test
    public void testHashService() {
        DefaultHashService hashService = new DefaultHashService(); //默认算法SHA-512
        hashService.setHashAlgorithmName("SHA-512");
        hashService.setPrivateSalt(new SimpleByteSource("123")); //私盐，默认无
        hashService.setGeneratePublicSalt(true);//是否生成公盐，默认false
        hashService.setRandomNumberGenerator(new SecureRandomNumberGenerator());//用于生成公盐。默认就这个
        hashService.setHashIterations(1); //生成Hash值的迭代次数

        HashRequest request = new HashRequest.Builder()
                .setAlgorithmName("MD5").setSource(ByteSource.Util.bytes("hello"))
                .setSalt(ByteSource.Util.bytes("123")).setIterations(2).build();
        String hex = hashService.computeHash(request).toHex();
        System.out.println(hex);
    }


    @Test
    public void testAesCipherService() {
        AesCipherService aesCipherService = new AesCipherService();
        aesCipherService.setKeySize(128);//设置key长度

        //生成key
        Key key = aesCipherService.generateNewKey();

        String text = "hello";

        //加密
        String encrptText = aesCipherService.encrypt(text.getBytes(), key.getEncoded()).toHex();
        //解密
        String text2 = new String(aesCipherService.decrypt(Hex.decode(encrptText), key.getEncoded()).getBytes());

        Assert.assertEquals(text, text2);
    }

    @Test
    public void testBlowfishCipherService() {
        BlowfishCipherService blowfishCipherService = new BlowfishCipherService();
        blowfishCipherService.setKeySize(128);

        //生成key
        Key key = blowfishCipherService.generateNewKey();

        String text = "hello";

        //加密
        String encrptText = blowfishCipherService.encrypt(text.getBytes(), key.getEncoded()).toHex();
        //解密
        String text2 = new String(blowfishCipherService.decrypt(Hex.decode(encrptText), key.getEncoded()).getBytes());

        Assert.assertEquals(text, text2);
    }

    @Test
    public void testDefaultBlockCipherService() throws Exception {


        //对称加密，使用Java的JCA（javax.crypto.Cipher）加密API，常见的如 'AES', 'Blowfish'
        DefaultBlockCipherService cipherService = new DefaultBlockCipherService("AES");
        cipherService.setKeySize(128);

        //生成key
        Key key = cipherService.generateNewKey();

        String text = "hello";

        //加密
        String encrptText = cipherService.encrypt(text.getBytes(), key.getEncoded()).toHex();
        //解密
        String text2 = new String(cipherService.decrypt(Hex.decode(encrptText), key.getEncoded()).getBytes());

        Assert.assertEquals(text, text2);
    }

    @Test
    public void testPasswordServiceWithMyRealm() {
        login("classpath:shiro-passwordservice.ini", "wu", "123");
    }
    @Test
    public void testPasswordServiceWithJdbcRealm() {
        login("classpath:shiro-jdbc-passwordservice.ini", "wu", "123");
    }
    @Test
    public void testGeneratePassword() {
        String algorithmName = "md5";
        String username = "liu";
        String password = "123";
        String salt1 = username;
        String salt2 = new SecureRandomNumberGenerator().nextBytes().toHex();
        int hashIterations = 2;

        SimpleHash hash = new SimpleHash(algorithmName, password, salt1 + salt2, hashIterations);
        String encodedPassword = hash.toHex();
        System.out.println(salt2);
        System.out.println(encodedPassword);
    }
    @Test
    public void testHashedCredentialsMatcherWithMyRealm2() {
        //使用testGeneratePassword生成的散列密码
        login("classpath:shiro-hashedCredentialsMatcher.ini", "liu", "123");
    }
    @Test
    public void testHashedCredentialsMatcherWithJdbcRealm() {

        BeanUtilsBean.getInstance().getConvertUtils().register(new EnumConverter(), JdbcRealm.SaltStyle.class);

        //使用testGeneratePassword生成的散列密码
        login("classpath:shiro-jdbc-hashedCredentialsMatcher.ini", "liu", "123");
    }
    private class EnumConverter extends AbstractConverter {
        @Override
        protected String convertToString(final Object value) throws Throwable {
            return ((Enum) value).name();
        }
        @Override
        protected Object convertToType(final Class type, final Object value) throws Throwable {
            return Enum.valueOf(type, value.toString());
        }

        @Override
        protected Class getDefaultType() {
            return null;
        }

    }
    @Test()
    public void testRetryLimitHashedCredentialsMatcherWithMyRealm() {
        for(int i = 1; i <= 5; i++) {
            try {
                login("classpath:shiro-retryLimitHashedCredentialsMatcher.ini", "liu", "234");
            } catch (Exception e) {/*ignore*/}
        }
        login("classpath:shiro-retryLimitHashedCredentialsMatcher.ini", "liu", "234");
    }

}
