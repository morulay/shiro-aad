package com.github.morulay.shiro.aad;

public interface PrincipalFactory {

  Object createPrincipal(String username);
}
