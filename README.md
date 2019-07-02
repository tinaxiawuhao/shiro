#Shiro安全框架
##什么是Shiro
###什么是Shiro
```
Apache Shiro是一个强大且易用的Java安全框架,执行身份验证、授权、密码和会话管理。使用Shiro的易于理解的
API,您可以快速、轻松地获得任何应用程序,从最小的移动应用程序到最大的网络和企业应用程序。
Apache Shiro 的首要目标是易于使用和理解。安全有时候是很复杂的，甚至是痛苦的，但它没有必要这样。框架
应该尽可能掩盖复杂的地方，露出一个干净而直观的 API，来简化开发人员在使他们的应用程序安全上的努力。以
下是你可以用 Apache Shiro 所做的事情：
验证用户来核实他们的身份
对用户执行访问控制，如：
判断用户是否被分配了一个确定的安全角色
判断用户是否被允许做某事
在任何环境下使用 Session API，即使没有 Web 或 EJB 容器。
在身份验证，访问控制期间或在会话的生命周期，对事件作出反应。
聚集一个或多个用户安全数据的数据源，并作为一个单一的复合用户“视图”。
启用单点登录（SSO）功能。
为没有关联到登录的用户启用"Remember Me"服务
```
###与Spring Security的对比
####Shiro：
```
Shiro较之 Spring Security，Shiro在保持强大功能的同时，还在简单性和灵活性方面拥有巨大优势。
1. 易于理解的 Java Security API；
2. 简单的身份认证（登录），支持多种数据源（LDAP，JDBC，Kerberos，ActiveDirectory 等）；
3. 对角色的简单的签权（访问控制），支持细粒度的签权；
4. 支持一级缓存，以提升应用程序的性能；
5. 内置的基于 POJO 企业会话管理，适用于 Web 以及非 Web 的环境；
6. 异构客户端会话访问；
7. 非常简单的加密 API；
8. 不跟任何的框架或者容器捆绑，可以独立运行
```
####Spring Security：
```
除了不能脱离Spring，shiro的功能它都有。而且Spring Security对Oauth、OpenID也有支持,Shiro则需要自己手
动实现。Spring Security的权限细粒度更高。
```
### Shiro的功能模块

####Shiro可以非常容易的开发出足够好的应用，其不仅可以用在JavaSE环境，也可以用在JavaEE环境。Shiro可以帮助我们完成：认证、授权、加密、会话管理、与Web集成、缓存等。这不就是我们想要的嘛，而且Shiro的API也是非常简单；其基本功能点如下图所示：
```
Authentication：身份认证/登录，验证用户是不是拥有相应的身份。
Authorization：授权，即权限验证，验证某个已认证的用户是否拥有某个权限；即判断用户是否能做事情。
Session Management：会话管理，即用户登录后就是一次会话，在没有退出之前，它的所有信息都在会话中；会话可以是普通JavaSE环境的，也可以是如Web环境的。
Cryptography：加密，保护数据的安全性，如密码加密存储到数据库，而不是明文存储。
Web Support：Shiro 的 web 支持的 API 能够轻松地帮助保护 Web 应用程序。
Caching：缓存，比如用户登录后，其用户信息、拥有的角色/权限不必每次去查，这样可以提高效率。
Concurrency：Apache Shiro 利用它的并发特性来支持多线程应用程序。
Testing：测试支持的存在来帮助你编写单元测试和集成测试，并确保你的能够如预期的一样安全。
"Run As"：一个允许用户假设为另一个用户身份（如果允许）的功能，有时候在管理脚本很有用。
"Remember Me"：记住我。
```
##Shiro的内部结构
```
Subject：主体，可以看到主体可以是任何可以与应用交互的“用户”；
SecurityManager：相当于SpringMVC中的DispatcherServlet或者Struts2中的FilterDispatcher；是Shiro的心脏；所有具体的交互都通过SecurityManager进行控制；它管理着所有Subject、且负责进行认证和授权、及会话、缓存的管理。
Authenticator：认证器，负责主体认证的，这是一个扩展点，如果用户觉得Shiro默认的不好，可以自定义实现；其需要认证策略（Authentication Strategy），即什么情况下算用户认证通过了；
Authrizer：授权器，或者访问控制器，用来决定主体是否有权限进行相应的操作；即控制着用户能访问应用中的哪些功能；
Realm：可以有1个或多个Realm，可以认为是安全实体数据源，即用于获取安全实体的；可以是JDBC实现，也可以是LDAP实现，或者内存实现等等；由用户提供；注意：Shiro不知道你的用户/权限存储在哪及以何种格式存储；所以我们一般在应用中都需要实现自己的Realm；
SessionManager：如果写过Servlet就应该知道Session的概念，Session呢需要有人去管理它的生命周期，这个组件就是SessionManager；而Shiro并不仅仅可以用在Web环境，也可以用在如普通的JavaSE环境、EJB等环境；所有呢，Shiro就抽象了一个自己的Session来管理主体与应用之间交互的数据；
SessionDAO：DAO大家都用过，数据访问对象，用于会话的CRUD，比如我们想把Session保存到数据库，那么可以实现自己的SessionDAO，通过如JDBC写到数据库；比如想把Session放到Memcached中，可以实现自己的
Memcached SessionDAO；另外SessionDAO中可以使用Cache进行缓存，以提高性能；
CacheManager：缓存控制器，来管理如用户、角色、权限等的缓存的；因为这些数据基本上很少去改变，放到缓存中后可以提高访问的性能
Cryptography：密码模块，Shiro提高了一些常见的加密组件用于如密码加密/解密的。
```
##应用程序使用Shiro
####也就是说对于我们而言，最简单的一个Shiro应用：
```
1、应用代码通过Subject来进行认证和授权，而Subject又委托给SecurityManager；
2、我们需要给Shiro的SecurityManager注入Realm，从而让SecurityManager能得到合法的用户及其权限进行判断。
从以上也可以看出，Shiro不提供维护用户/权限，而是通过Realm让开发人员自己注入。
```
##Shiro的入门
```
（1）创建工程导入shiro坐标
<dependencies>
    <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-core</artifactId>
        <version>1.3.2</version>
    </dependency>
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.12</version>
        <scope>test</scope>
    </dependency>
</dependencies>

```
###用户认证
####认证：身份认证/登录，验证用户是不是拥有相应的身份。基于shiro的认证，是通过subject的login方法完成用户认证工作的
```
（1）在resource目录下创建shiro的ini配置文件构造模拟数据（shiro-auth.ini）
[users]
#模拟从数据库查询的用户
#数据格式 用户名=密码
zhangsan=123456
lisi=654321

（2）测试用户认证
@Test
public void testLogin() throws Exception{
    //1.加载ini配置文件创建SecurityManager
    Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
    //2.获取securityManager
    SecurityManager securityManager = factory.getInstance();
    //3.将securityManager绑定到当前运行环境
    SecurityUtils.setSecurityManager(securityManager);
    //4.创建主体(此时的主体还为经过认证)
    Subject subject = SecurityUtils.getSubject();
    /**
    * 模拟登录，和传统等不同的是需要使用主体进行登录
    */
    //5.构造主体登录的凭证（即用户名/密码）
    //第一个参数：登录用户名，第二个参数：登录密码
    UsernamePasswordToken upToken = new UsernamePasswordToken("zhangsan","123456");
    //6.主体登录
    subject.login(upToken);
    //7.验证是否登录成功
    System.out.println("用户登录成功="+subject.isAuthenticated());
    //8.登录成功获取数据
    //getPrincipal 获取登录成功的安全数据
    System.out.println(subject.getPrincipal());
}
```
###用户授权
####授权，即权限验证，验证某个已认证的用户是否拥有某个权限；即判断用户是否能做事情，常见的如：验证某个用户是否拥有某个角色。或者细粒度的验证某个用户对某个资源是否具有某个权限
```
（1）在resource目录下创建shiro的ini配置文件构造模拟数据（shiro-prem.ini）
[users]
#模拟从数据库查询的用户
#数据格式 用户名=密码,角色1,角色2..
zhangsan=123456,role1,role2
lisi=654321,role2
[roles]
#模拟从数据库查询的角色和权限列表
#数据格式 角色名=权限1，权限2
role1=user:save,user:update
role2=user:update,user.delete
role3=user.find

（2）完成用户授权
public class ShiroTest1 {
@Test
public void testLogin() throws Exception{
    //1.加载ini配置文件创建SecurityManager
    Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
    //2.获取securityManager
    SecurityManager securityManager = factory.getInstance();
    //3.将securityManager绑定到当前运行环境
    SecurityUtils.setSecurityManager(securityManager);
    //4.创建主体(此时的主体还为经过认证)
    Subject subject = SecurityUtils.getSubject();
    /**
    * 模拟登录，和传统等不同的是需要使用主体进行登录
    */
    //5.构造主体登录的凭证（即用户名/密码）
    //第一个参数：登录用户名，第二个参数：登录密码
    UsernamePasswordToken upToken = new UsernamePasswordToken("lisi","654321");
    //6.主体登录
    subject.login(upToken);
    //7.用户认证成功之后才可以完成授权工作
    boolean hasPerm = subject.isPermitted("user:save");
    System.out.println("用户是否具有save权限="+hasPerm);
}

```
###自定义Realm
####Realm域：Shiro从Realm获取安全数据（如用户、角色、权限），就是说SecurityManager要验证用户身份，那么它需要从Realm获取相应的用户进行比较以确定用户身份是否合法；也需要从Realm得到用户相应的角色/权限进行验证用户是否能进行操作；可以把Realm看成DataSource，即安全数据源
```
（1）自定义Realm
/**
* 自定义realm，需要继承AuthorizingRealm父类
* 重写父类中的两个方法
* doGetAuthorizationInfo ：授权
* doGetAuthenticationInfo ：认证
*/
public class PermissionRealm extends AuthorizingRealm {
    @Override
    public void setName(String name) {
         super.setName("permissionRealm");
    }
    /**
    * 授权：授权的主要目的就是查询数据库获取用户的所有角色和权限信息
    */
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        // 1.从principals获取已认证用户的信息
        String username = (String) principalCollection.getPrimaryPrincipal();
        /**
        * 正式系统：应该从数据库中根据用户名或者id查询
        * 这里为了方便演示，手动构造
        */
        // 2.模拟从数据库中查询的用户所有权限
        List<String> permissions = new ArrayList<String>();
        permissions.add("user:save");// 用户的创建
        permissions.add("user:update");// 商品添加权限
       // 3.模拟从数据库中查询的用户所有角色
       List<String> roles = new ArrayList<String>();
       roles.add("role1");
       roles.add("role2");
       // 4.构造权限数据
       SimpleAuthorizationInfo simpleAuthorizationInfo = new
       SimpleAuthorizationInfo();
       // 5.将查询的权限数据保存到simpleAuthorizationInfo
       simpleAuthorizationInfo.addStringPermissions(permissions);
       // 6.将查询的角色数据保存到simpleAuthorizationInfo
       simpleAuthorizationInfo.addRoles(roles);
       return simpleAuthorizationInfo;
    }
   /**
   * 认证：认证的主要目的，比较用户输入的用户名密码是否和数据库中的一致
   */
   protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
       //1.获取登录的upToken
       UsernamePasswordToken upToken = (UsernamePasswordToken)authenticationToken;
       //2.获取输入的用户名密码
       String username = upToken.getUsername();
       String password = new String(upToken.getPassword());
       /**
       * 3.验证用户名密码是否正确
       * 正式系统：应该从数据库中查询用户并比较密码是否一致
       * 为了测试，只要输入的密码为123456则登录成功
       */
       if(!password.equals("123456")) {
            throw new RuntimeException("用户名或密码错误");//抛出异常表示认证失败
       }else{
           SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(username,
           password,
           this.getName());
           return info;
       }
   }
}
```
###配置shiro的ini配置文件（shiro-realm.ini）
```

[main]
#声明realm
permReam=cn.itcast.shiro.PermissionRealm
#注册realm到securityManager中
securityManager.realms=$permReam
```
###验证
```
public class ShiroTest2 {
    private SecurityManager securityManager;
    @Before
    public void init() throws Exception{
        //1.加载ini配置文件创建SecurityManager
        Factory<SecurityManager> factory = new
        IniSecurityManagerFactory("classpath:shiro-realm.ini");
        //2.获取securityManager
        SecurityManager securityManager = factory.getInstance();
        //13.将securityManager绑定到当前运行环境
        SecurityUtils.setSecurityManager(securityManager);
    }
    @Test
    public void testLogin() throws Exception{
        //1.创建主体(此时的主体还为经过认证)
        Subject subject = SecurityUtils.getSubject();
        //2.构造主体登录的凭证（即用户名/密码）
        UsernamePasswordToken upToken = new UsernamePasswordToken("lisi","123456");
        //3.主体登录
        subject.login(upToken);
        //登录成功验证是否具有role1角色
        //System.out.println("当前用户具有role1="+subject.hasRole("role3"));
        //登录成功验证是否具有某些权限
        System.out.println("当前用户具有user:save权限="+subject.isPermitted("user:save"));
    }
}
```
###认证与授权的执行流程分析
####认证流程
```
1. 首先调用Subject.login(token)进行登录，其会自动委托给Security Manager，调用之前必须通过
SecurityUtils. setSecurityManager()设置；
2. SecurityManager负责真正的身份验证逻辑；它会委托给Authenticator进行身份验证；
3. Authenticator才是真正的身份验证者，Shiro API中核心的身份认证入口点，此处可以自定义插入自己的实现；
4. Authenticator可能会委托给相应的AuthenticationStrategy进行多Realm身份验证，默认
ModularRealmAuthenticator会调用AuthenticationStrategy进行多Realm身份验证；
5. Authenticator会把相应的token传入Realm，从Realm获取身份验证信息，如果没有返回/抛出异常表示身份
验证失败了。此处可以配置多个Realm，将按照相应的顺序及策略进行访问。
```
####授权流程
```
1. 首先调用Subject.isPermitted/hasRole接口，其会委托给SecurityManager，而SecurityManager接着会委托给Authorizer；
2. Authorizer是真正的授权者，如果我们调用如isPermitted(“user:view”)，其首先会通过PermissionResolver把字符串转换成相应的Permission实例；
3. 在进行授权之前，其会调用相应的Realm获取Subject相应的角色/权限用于匹配传入的角色/权限；
4. Authorizer会判断Realm的角色/权限是否和传入的匹配，如果有多个Realm，会委托给ModularRealmAuthorizer进行循环判断，如果匹配如isPermitted/hasRole会返回true，否则返回false表示授权失败
```
