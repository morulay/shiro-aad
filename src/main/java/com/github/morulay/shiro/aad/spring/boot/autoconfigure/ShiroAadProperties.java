package com.github.morulay.shiro.aad.spring.boot.autoconfigure;

import javax.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Configuration properties for Shiro integration with Azure AD */
@Validated
@ConfigurationProperties(prefix = "shiro.aad")
public class ShiroAadProperties {

  /** Whether to enable Azure AD integration */
  private boolean enabled = true;

  /** Name of the tenant */
  @NotBlank private String tenant;

  /** Tenant ID of the tenant */
  @NotBlank private String tenantId;

  /**
   * Microsoft authority instance base URL. Default value is {@code
   * https://login.microsoftonline.com}
   */
  private String authority = "https://login.microsoftonline.com";

  /**
   * Unique application (client) ID assigned to your application by Azure AD when the application
   * was registered
   */
  @NotBlank private String clientId;

  /** Secret (password) provided by the application registration portal */
  private String clientSecret;

  /** URI where the identity provider will send the security tokens back to */
  private String redirectUri = "/";

  /** URI that the user is redirected to after successfully signing out */
  private String postLogoutUri;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(boolean enabled) {
    this.enabled = enabled;
  }

  public String getTenant() {
    return tenant;
  }

  public void setTenant(String tenant) {
    this.tenant = tenant;
  }

  public String getTenantId() {
    return tenantId;
  }

  public void setTenantId(String tenantId) {
    this.tenantId = tenantId;
  }

  public String getAuthority() {
    return authority;
  }

  public void setAuthority(String authority) {
    this.authority = authority;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public String getPostLogoutUri() {
    return postLogoutUri;
  }

  public void setPostLogoutUri(String postLogoutUri) {
    this.postLogoutUri = postLogoutUri;
  }
}
