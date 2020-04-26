package com.github.morulay.shiro.aad.spring.boot.autoconfigure;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "shiro.aad")
public class ShiroAadProperties {
  private String tenant;
  private String tenantId;
  private String authority = "https://login.microsoftonline.com";
  private String clientId;
  private String redirectUri = "/";
}
