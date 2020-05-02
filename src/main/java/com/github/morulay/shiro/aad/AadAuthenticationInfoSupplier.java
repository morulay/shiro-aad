package com.github.morulay.shiro.aad;

import static java.lang.String.format;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AadAuthenticationInfoSupplier implements Authenticator {

  private static final Logger log = LoggerFactory.getLogger(AadAuthenticationInfoSupplier.class);

  private String authority;
  private String tenantId;
  private String clientId;
  private PrincipalFactory principalFactory;

  public AadAuthenticationInfoSupplier(
      String authority, String tenantId, String clientId, PrincipalFactory principalFactory) {
    this.authority = authority;
    this.tenantId = tenantId;
    this.clientId = clientId;
    this.principalFactory = principalFactory;
  }

  @Override
  public AuthenticationInfo authenticate(AuthenticationToken token) {
    if (!supports(token)) {
      throw new AuthenticationException("Not supported token");
    }

    OpenIdToken idToken = (OpenIdToken) token;
    JWTClaimsSet claims = null;
    try {
      claims = validateToken(idToken.getToken());
    } catch (Exception e) {
      log.warn("Unable to validate OpenID token", e);
      throw new AuthenticationException("Unable to validate OpenID token");
    }

    String username;
    try {
      username = claims.getStringClaim("preferred_username");
    } catch (ParseException e) {
      log.warn("Unable to get " + "preferred_username", e);
      throw new AuthenticationException("Unable to validate OpenID token");
    }

    SimplePrincipalCollection principals = new SimplePrincipalCollection();
    principals.add(username, "Azure Active Directory realm");
    principals.add(idToken, "Azure Active Directory realm");
    principals.add(principalFactory.createPrincipal(username), "Application realm");
    return new SimpleAuthenticationInfo(
        principalFactory.createPrincipal(username),
        token.getCredentials(),
        "Azure Active Directory realm");
  }

  private boolean supports(AuthenticationToken token) {
    return token instanceof OpenIdToken;
  }

  private JWTClaimsSet validateToken(String idToken) throws Exception {
    // Create a JWT processor for the access tokens
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
    jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("jwt")));

    JWKSource<SecurityContext> keySource =
        new RemoteJWKSet<>(new URL(format("%s/%s/discovery/v2.0/keys", authority, tenantId)));
    JWSKeySelector<SecurityContext> keySelector =
        new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource);
    jwtProcessor.setJWSKeySelector(keySelector);

    jwtProcessor.setJWTClaimsSetVerifier(
        new DefaultJWTClaimsVerifier<SecurityContext>(
            new JWTClaimsSet.Builder()
                .issuer(format("%s/%s/v2.0", authority, tenantId))
                .audience(clientId)
                .build(),
            new HashSet<String>(
                Arrays.asList("sub", "iat", "exp", "nonce", "preferred_username"))));
    return jwtProcessor.process(idToken, null);
  }
}
