package com.github.morulay.shiro.aad;

import static java.lang.String.format;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AadAuthenticator implements Authenticator {

  private static final String CLAIM_PREFERRED_USERNAME = "preferred_username";

  private static final Logger log = LoggerFactory.getLogger(AadAuthenticator.class);

  private String authority;
  private String tenantId;
  private String clientId;
  private String realmName;
  private PrincipalFactory principalFactory;

  /**
   * @param authority the Microsoft authority instance base URI, e.g. {@code
   *     https://login.microsoftonline.com}
   * @param tenantId the ID of the tenant
   * @param clientId the ID assigned to your application by Azure AD when the application was
   *     registered
   * @param realmName the authorization realm name
   * @param principalFactory optional {@link PrincipalFactory} instance to take control on primary
   *     principal creation
   */
  public AadAuthenticator(
      String authority,
      String tenantId,
      String clientId,
      String realmName,
      PrincipalFactory principalFactory) {
    this.authority = authority;
    this.tenantId = tenantId;
    this.clientId = clientId;
    this.realmName = realmName;
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
    return new SimpleAuthenticationInfo(principal, token.getCredentials(), realmName);
  }

  private boolean supports(AuthenticationToken token) {
    return token instanceof OpenIdToken;
  }

  private JWTClaimsSet validateToken(String idToken)
      throws MalformedURLException, ParseException, BadJOSEException, JOSEException {
    // Create a JWT processor for the access tokens
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
    jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("jwt")));

    JWKSource<SecurityContext> keySource =
        new RemoteJWKSet<>(new URL(format("%s/%s/discovery/v2.0/keys", authority, tenantId)));
    JWSKeySelector<SecurityContext> keySelector =
        new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource);
    jwtProcessor.setJWSKeySelector(keySelector);

    jwtProcessor.setJWTClaimsSetVerifier(
        new DefaultJWTClaimsVerifier<>(
            new JWTClaimsSet.Builder()
                .issuer(format("%s/%s/v2.0", authority, tenantId))
                .audience(clientId)
                .build(),
            new HashSet<>(Arrays.asList("sub", "iat", "exp", "nonce", CLAIM_PREFERRED_USERNAME))));
    return jwtProcessor.process(idToken, null);
  }
}
