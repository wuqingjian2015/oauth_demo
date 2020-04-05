# oauth_demo
spring boot oauth2 sample

心得：
学习目的：
1. 了解Oauth2机制。
2. 了解Spring boot中如何使用SDK从而实现oauth2认证服务器。

配置oauth2认证服务器，需要引入依赖：
 implementation 'org.springframework.security.oauth.boot:spring-security-oauth2-autoconfigure:2.2.5.RELEASE'

源代码中需要注入
  @Configuration
  @EnableAuthorizationServer
  并重载AuthorizationServerConfigurerAdapter的configure的各个方法。
  在以ClientDetailsServiceConfigurer为形参的configure的重载实现中，指明client信息：id,grant_type,secret
  举例：
  
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
      clients.inMemory().withClient("client_1")
        .resourceIds(DEMO_RESOURCE_ID)
        .authorizedGrantTypes("client_credentials", "refresh_token")
        .scopes("select")
        .authorities("USER")
        .secret(new BCryptPasswordEncoder().encode("123456"))
        .and()
        .withClient("client_2")
        .resourceIds(DEMO_RESOURCE_ID)
        .authorizedGrantTypes("password", "refresh_token")
        .scopes("select")
        .authorities("USER")
        .secret(new BCryptPasswordEncoder().encode("123456")); 
    }

结果：
>curl -X POST localhost:8080/oauth/token -dgrant_type=client_credentials -dclient_id=client_1 -dclient_secret=123456 -i
HTTP/1.1 200
Cache-Control: no-store
Pragma: no-cache
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Content-Type: application/json;charset=UTF-8       
Transfer-Encoding: chunked
Date: Sat, 28 Mar 2020 14:14:34 GMT

{"access_token":"ccf3468f-5d61-4a92-87b7-4be10119b758","token_type":"bearer","expires_in":43181,"scope":"select"}
出现这个结果说明/oauth/token获取到access_token，可以进一步以这个access_token访问被限制的资源。这里注意参数与代码中的对应关系。因为在代码中配置client_1的grant_type为client_credentials，client_id和client_secret三者都符合，所以通过了认证，获取到token。下一个例子，client_1的grant_type为password，结果没有通过认证，报出invalid_client。

C:\work\java\oautho_maven>curl -X POST localhost:8080/oauth/token -dgrant_type=client_credentials -dclient_id=client_2 -dclient_secret=123456 -i
HTTP/1.1 401 
Cache-Control: no-store
Pragma: no-cache
WWW-Authenticate: Bearer error="invalid_client", error_description="Unauthorized grant type: client_credentials"
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Sat, 28 Mar 2020 14:15:33 GMT

{"error":"invalid_client","error_description":"Unauthorized grant type: client_credentials"}
>curl -X POST localhost:8080/oauth/token -dgrant_type=password -dclient_id=client_2 -dclient_secret=123456 -i
HTTP/1.1 500
Cache-Control: no-store
Pragma: no-cache
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Sat, 28 Mar 2020 14:15:47 GMT
Connection: close

{"error":"server_error","error_description":"Internal Server Error"}
尝试用client_2获取认证，虽然grant_type, client_id, client_secret三者都相符，但因为这是password模式，咱们需要追加提供用户、密码的方式来访问。
>curl -X POST localhost:8080/oauth/token -dusername=user_1 -dpassword=123456 
-dgrant_type=password -dclient_id=client_2 -dclient_secret=123456 -i
HTTP/1.1 500
Cache-Control: no-store
Pragma: no-cache
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Content-Type: application/json
Transfer-Encoding: chunked
Date: Sat, 28 Mar 2020 14:55:35 GMT
Connection: close

{"error":"server_error","error_description":"Internal Server Error"}

综上所述，如果采用客户端模式来获取access_token的话，以上配置已经足够了。
如果采用密码模式的话，还需要配置用户访问信息。这些信息需要重载WebSecurityConfigurerAdapter的userDetailsService()时，提供用户信息。在访问/oauth/token时，增加用户、password，原来的grant_type、client_id、client_secret也同样不能缺少。

  @Bean 
  @Override
  protected UserDetailsService userDetailsService(){
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(); 
    manager.createUser(User.withUsername("user_1").password(new BCryptPasswordEncoder().encode("123456")).authorities("USER").build());
    manager.createUser(User.withUsername("user_2").password(new BCryptPasswordEncoder().encode("123456")).authorities("USER").build());
    return manager; 
  }
 结果：
 C:\work\java\oautho_maven>curl -X POST localhost:8080/oauth/token -dusername=user_1 -dpassword=123456 
-dgrant_type=password -dclient_id=client_2 -dclient_secret=123456 -i
HTTP/1.1 200
Cache-Control: no-store
Pragma: no-cache
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Content-Type: application/json;charset=UTF-8       
Transfer-Encoding: chunked
Date: Sat, 28 Mar 2020 15:00:17 GMT

{"access_token":"b970784f-01c6-4619-ba35-fa606852d4b6","token_type":"bearer","refresh_token":"18b9a964-beaf-45a0-b3b4-650b8eda0fac","expires_in":43199,"scope":"select"}

授权码模式：
1. 在注入@EnableAuthorizationServer的扩展AuthorizationServerConfigurerAdapter的类的configure中，用形参ClientDetailsServiceConfigurer增加一个客户端，其grant_type为Authorization_code。
2. @EnableWebSecurity应该同时应用。
3. 对于需要授权访问的资源，目前服务启动之前就预设好，或者重启后才能发挥作用。
4. 配置后，访问方式：
   A）当访问/oauth/authorize时，以client_id, response_type=code和redirect_uri=为参数，
   B）/oauth/authorize会导航到登录页面，用户登录成功后，
   C) 会导航到用户授权页面。
   D) 一旦授权许可后，会被导航到redirect_uri路径。
 访问例子
 http://localhost:8080/oauth/authorize?response_type=code&client_id=client_3&redirect_uri=http://localhost:8080/order/2
 
 最终会以http://localhost:8080/order/2?code=liMtsZ的形式，访问redirect_uri。
 
 简化模式
1. 在注入@EnableAuthorizationServer的扩展AuthorizationServerConfigurerAdapter的类的configure中，用形参ClientDetailsServiceConfigurer增加一个客户端，其grant_type为implicit。
2. @EnableWebSecurity应该同时应用。
3. 对于需要授权访问的资源，目前服务启动之前就预设好，或者重启后才能发挥作用。
使用方式：
 http://localhost:8080/oauth/authorize?response_type=token&client_id=client_4&redirect_uri=http://localhost:8080/order/2
 结果：
 http://localhost:8080/order/2#access_token=a27cc6c6-f6a6-49ba-9b87-1af4253699b1&token_type=bearer&expires_in=43199&scope=app
 
 通过比较这四种模式，需要人为参与授权的是：授权码模式和简化模式。不需要人为授权的模式是客户端模式和密码模式，可以用在RESTful API的权限访问限制中。
 
