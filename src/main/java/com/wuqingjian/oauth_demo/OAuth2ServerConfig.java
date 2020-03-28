package com.wuqingjian.oauth_demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AliasFor;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
public class OAuth2ServerConfig {
  private static final String DEMO_RESOURCE_ID = "order"; 

  @Bean 
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder(); 
  }

  @Configuration
  @EnableResourceServer
  protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
    @Override
    public void configure(ResourceServerSecurityConfigurer resources){
      resources.resourceId(DEMO_RESOURCE_ID).stateless(true);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
      http
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        .and()
        .requestMatchers().anyRequest()
        .and()
        .anonymous()
        .and()
        .authorizeRequests()
        .antMatchers("/order/**").authenticated(); 
    }
  }

  @Configuration
  @EnableAuthorizationServer
  protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    // @Bean 
    // public AuthenticationProvider authenticationProvider(){
    //   return new AuthenticationProvider(){
      
    //     @Override
    //     public boolean supports(Class<?> authentication) {
    //       // TODO Auto-generated method stub
    //       return false;
    //     }
      
    //     @Override
    //     public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    //       // TODO Auto-generated method stub
    //       return null;
    //     }
    //   };
    // }

    // @Bean 
    // @Override 
    // public AuthenticationManager authenticationManagerBean(){

    // }

    @Autowired
    private AuthenticationManager authenticationManager; 

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

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

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
      endpoints
        // .tokenStore(new RedisTokenStore(redisConnectionFactory))
        // .tokenStore(new DefaultTokenStore())
        .authenticationManager(authenticationManager); 

        // .authenticationManager(new AuthenticationManager(){
        
        //   @Override
        //   public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //     // TODO Auto-generated method stub
        //     return authenticationProvider().authenticate(authentication);
        //   }
        // }); 
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
      oauthServer.allowFormAuthenticationForClients(); 
    }
  }
}