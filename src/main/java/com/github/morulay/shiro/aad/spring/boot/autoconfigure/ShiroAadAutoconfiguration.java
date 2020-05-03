package com.github.morulay.shiro.aad.spring.boot.autoconfigure;

import com.github.morulay.shiro.aad.AadAuthenticator;
import com.github.morulay.shiro.aad.AadOpenIdAuthenticationFilter;
import com.github.morulay.shiro.aad.CookieRunAsFilter;
import com.github.morulay.shiro.aad.PrincipalFactory;
import com.github.morulay.shiro.session.HttpRequestSessionManager;
import javax.annotation.PostConstruct;
import javax.servlet.Filter;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;

@Configuration
@AutoConfigureBefore(ShiroWebAutoConfiguration.class)
@EnableConfigurationProperties(ShiroAadProperties.class)
@ConditionalOnProperty(name = "shiro.aad.enabled", havingValue = "true", matchIfMissing = true)
public class ShiroAadAutoconfiguration {

  @Autowired private ShiroAadProperties aadProperties;

  @Bean
  public Filter authcOpenId(SecurityManager securityManager) {
    return new AadOpenIdAuthenticationFilter(
        aadProperties.getAuthority(),
        aadProperties.getTenant(),
        aadProperties.getRedirectUri(),
        aadProperties.getClientId(),
        "");
  }

  @Bean
  public Filter cookieRunAs(SecurityManager securityManager) {
    return new CookieRunAsFilter();
  }

  @Bean
  @DependsOn({"authcOpenId", "cookieRunAs"})
  @ConditionalOnMissingBean
  public ShiroFilterChainDefinition shiroFilterChainDefinition() {
    DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();
    chainDefinition.addPathDefinition("/**", "authcOpenId, cookieRunAs");
    return chainDefinition;
  }

  @Bean
  public Authenticator authenticator(
      @Autowired(required = false) PrincipalFactory principalFactory) {
    return new AadAuthenticator(
        aadProperties.getAuthority(),
        aadProperties.getTenantId(),
        aadProperties.getClientId(),
        principalFactory);
  }

  @Bean
  public WebSessionManager sessionManager() {
    return new HttpRequestSessionManager();
  }

  @Configuration
  static class SecurityManagerPostConfig {

    @Autowired(required = false)
    private SecurityManager securityManager;

    @PostConstruct
    public void disableRememberMeManager() {
      if (securityManager instanceof DefaultWebSecurityManager) {
        ((DefaultWebSecurityManager) securityManager).setRememberMeManager(null);
      }
    }
  }
}
