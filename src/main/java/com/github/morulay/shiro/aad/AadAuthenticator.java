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
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LogoutAware;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AadAuthenticator implements Authenticator, LogoutAware {

  private static final String CLAIM_PREFERRED_USERNAME = "preferred_username";

  private static final Logger log = LoggerFactory.getLogger(AadAuthenticator.class);

  private String authority;
  private String tenantId;
  private String clientId;
  private PrincipalFactory principalFactory;

  public AadAuthenticator(
      String authority, String tenantId, String clientId, PrincipalFactory principalFactory) {
    this.authority = authority;
    this.tenantId = tenantId;
    this.clientId = clientId;
    this.principalFactory = principalFactory;
  }

  @Override
  public AuthenticationInfo authenticate(AuthenticationToken token) {
    if (!supports(token)) {
      log.warn("Not supported token [{}]", token.getClass());
      throw new IncorrectCredentialsException();
    }

    OpenIdToken idToken = (OpenIdToken) token;
    JWTClaimsSet claims = null;
    try {
      claims = validateToken(idToken.getToken());
    } catch (Exception e) {
      log.warn("Failed to validate OpenID token", e);
      throw new IncorrectCredentialsException();
    }

    String username;
    try {
      username = claims.getStringClaim(CLAIM_PREFERRED_USERNAME);
    } catch (ParseException e) {
      log.warn("Unable to get " + CLAIM_PREFERRED_USERNAME, e);
      throw new IncorrectCredentialsException();
    }

    Object principal =
        principalFactory != null ? principalFactory.createPrincipal(username) : username;
    return new SimpleAuthenticationInfo(
        principal, token.getCredentials(), "Azure Active Directory realm");
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
                Arrays.asList("sub", "iat", "exp", "nonce", CLAIM_PREFERRED_USERNAME))));
    return jwtProcessor.process(idToken, null);
  }

  @Override
  public void onLogout(PrincipalCollection principals) {
    // TODO Auto-generated method stub

  }
}