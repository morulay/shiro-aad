package com.github.morulay.shiro.aad;

import org.apache.shiro.authc.HostAuthenticationToken;

public class OpenIdToken implements HostAuthenticationToken {

  private static final long serialVersionUID = -7623895973122361884L;

  private final String token;

  /**
   * The location from where the login attempt occurs, or <code>null</code> if not known or
   * explicitly omitted.
   */
  private String host;

  public OpenIdToken(String token) {
    this(token, null);
  }

  public OpenIdToken(String token, String host) {
    this.token = token;
    this.host = host;
  }

  @Override
  public Object getPrincipal() {
    return getToken();
  }

  @Override
  public Object getCredentials() {
    return getToken();
  }

  public String getToken() {
    return token;
  }

  @Override
  public String getHost() {
    return host;
  }
}
