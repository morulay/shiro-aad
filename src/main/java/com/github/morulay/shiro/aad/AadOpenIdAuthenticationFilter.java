package com.github.morulay.shiro.aad;

import static com.github.morulay.shiro.aad.AadUtils.toAbsoluteUri;
import static java.lang.String.format;
import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static org.apache.shiro.web.util.WebUtils.toHttp;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.BearerToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.Cookie.SameSiteOptions;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;

/**
 * Requires the requesting user to be {@link org.apache.shiro.subject.Subject#isAuthenticated()
 * authenticated} for the request to continue, and if they're not, requires the user to login via
 * Azure Active Directory. Upon successful login, they're allowed to continue on to the requested
 * resource/url.
 *
 * <p>This implementation is based on <a
 * href="https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens">Microsoft
 * identity platform ID tokens</a> and inspired by Microsoft's example of <a
 * href="https://github.com/Azure-Samples/ms-identity-java-webapp/tree/master/msal-java-webapp-sample">Java
 * Web application that signs in users with the Microsoft identity platform and calls Microsoft
 * Graph</a> and <a href="https://github.com/microsoft/azure-spring-boot">Azure Spring Boot</a>
 * starter.
 */
@SuppressWarnings("java:S110") // Parents come from external library
public class AadOpenIdAuthenticationFilter extends AuthenticatingFilter {

  private static final String INVALID_TOKEN_MSG = "Invalid OpenID Connect token";
  private static final String AUTH_ERROR_PARAM = "error";
  private static final String AUTH_CODE_PARAM = "code";
  private static final String ID_TOKEN_PARAM = "id_token";
  private static final String STATE_PARAM = "state";
  private static final String NONCE_PARAM = "nonce";
  private static final String TOKEN_PARAM = "token";
  private static final String TOKEN_PARAM_CHECK = "check";
  private static final String TOKEN_PARAM_REFRESH = "refresh";
  private static final String NEXT_CHECK_MIN_PARAM = "next_check_min";

  static final SimpleCookie ID_TOKEN_COOKIE_TEMPLATE = new SimpleCookie(ID_TOKEN_PARAM);
  private static final SimpleCookie STATE_COOKIE_TEMPLATE = new SimpleCookie(STATE_PARAM);
  private static final SimpleCookie NONCE_COOKIE_TEMPLATE = new SimpleCookie(NONCE_PARAM);

  private static final Logger LOG = LoggerFactory.getLogger(AadOpenIdAuthenticationFilter.class);

  private String authority;
  private String tenant;
  private String clientId;
  private String realmName;

  /**
   * @param authority the Microsoft authority instance base URI, e.g. {@code
   *     https://login.microsoftonline.com}
   * @param tenant the name of the tenant
   * @param redirectUri the URI where the identity provider will send the security tokens back to
   * @param clientId the ID assigned to your application by Azure AD when the application was
   *     registered
   * @param realmName the authorization realm name
   */
  public AadOpenIdAuthenticationFilter(
      String authority, String tenant, String redirectUri, String clientId, String realmName) {
    this.authority = authority;
    this.tenant = tenant;
    setLoginUrl(redirectUri);
    this.clientId = clientId;
    this.realmName = realmName;
  }

  @Override
  protected boolean onAccessDenied(ServletRequest request, ServletResponse response)
      throws Exception {
    HttpServletRequest httpRequest = WebUtils.toHttp(request);
    HttpServletResponse httpResponse = WebUtils.toHttp(response);

    if (hasAccessToken(httpRequest)) {
      return executeLogin(httpRequest, httpResponse);
    }

    if (isLoginRequest(httpRequest, httpResponse)) {
      processAuthenticationCodeRedirect(httpRequest, httpResponse);
      return false;
    }

    sendChallengeOrRedirectToLogin(httpRequest, httpResponse);
    return false;
  }

  private boolean hasAccessToken(HttpServletRequest request) {
    return ID_TOKEN_COOKIE_TEMPLATE.readValue(request, null) != null;
  }

  @Override
  protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
    HttpServletRequest httpRequest = toHttp(request);
    Map<String, String[]> httpParameters = httpRequest.getParameterMap();

    boolean isPost = httpRequest.getMethod().equalsIgnoreCase("POST");
    boolean hasError = httpParameters.containsKey(AUTH_ERROR_PARAM);
    boolean hasIdToken = httpParameters.containsKey(ID_TOKEN_PARAM);
    boolean hasCode = httpParameters.containsKey(AUTH_CODE_PARAM);

    return super.isLoginRequest(httpRequest, response)
        && isPost
        && (hasError || hasCode || hasIdToken);
  }

  private void processAuthenticationCodeRedirect(
      HttpServletRequest request, HttpServletResponse response)
      throws IOException, com.nimbusds.oauth2.sdk.ParseException {

    validateState(
        STATE_COOKIE_TEMPLATE.readValue(request, response),
        WebUtils.getCleanParam(request, STATE_PARAM));

    HTTPRequest httpRequest = ServletUtils.createHTTPRequest(request);
    AuthenticationResponse authResponse = AuthenticationResponseParser.parse(httpRequest);
    if (authResponse instanceof AuthenticationErrorResponse) {
      AuthenticationErrorResponse oidcResponse = (AuthenticationErrorResponse) authResponse;
      LOG.warn(
          "Authentication response indicates an error [{}: {}]",
          oidcResponse.getErrorObject().getCode(),
          oidcResponse.getErrorObject().getDescription());
      throw new AuthenticationException(INVALID_TOKEN_MSG);
    }

    AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;
    validateScope(oidcResponse);
    validateNonce(NONCE_COOKIE_TEMPLATE.readValue(request, response), oidcResponse);
    removeScopeAndNonceCookies(request, response);

    int idTokenCookieMaxAge = 60 * 60; // One hour
    try {
      Date expirationTime = oidcResponse.getIDToken().getJWTClaimsSet().getExpirationTime();
      idTokenCookieMaxAge = (int) ((expirationTime.getTime() - System.currentTimeMillis()) / 1000);
    } catch (ParseException e) {
      LOG.warn(
          format(
              "Unable to get ID token expiration time. The id_token cookie Max-Age is set to %s seconds",
              idTokenCookieMaxAge),
          e);
    }

    storeIdTokenAsCookie(
        request, response, oidcResponse.getIDToken().getParsedString(), idTokenCookieMaxAge);
    redirectToSavedRequest(request, response);
  }

  private void validateState(String stateCookie, String state) {
    if (!Objects.equals(stateCookie, state)) {
      LOG.warn(
          "Authentication response state [{}] differs from stored one [{}]", state, stateCookie);
      throw new AuthenticationException("Invalid state");
    }
  }

  private void validateScope(AuthenticationSuccessResponse oidcResponse) {
    if (oidcResponse.getIDToken() == null
        || oidcResponse.getAccessToken() != null
        || oidcResponse.getAuthorizationCode() != null) {
      throw new AuthenticationException("Authentication response has uunexpected set of artifacts");
    }
  }

  private void validateNonce(String nonceCookie, AuthenticationSuccessResponse oidcResponse) {
    String nonce;
    try {
      nonce = oidcResponse.getIDToken().getJWTClaimsSet().getStringClaim(NONCE_PARAM);
    } catch (ParseException e) {
      LOG.warn("Unable to parse the OpenID Connect token", e);
      throw new AuthenticationException(INVALID_TOKEN_MSG);
    }

    if (!Objects.equals(nonceCookie, nonce)) {
      LOG.warn(
          "Authentication response nonce [{}] differs from stored one [{}]", nonce, nonceCookie);
      throw new AuthenticationException(INVALID_TOKEN_MSG);
    }
  }

  private void removeScopeAndNonceCookies(
      HttpServletRequest request, HttpServletResponse response) {
    STATE_COOKIE_TEMPLATE.removeFrom(request, response);
    NONCE_COOKIE_TEMPLATE.removeFrom(request, response);
  }

  private void storeIdTokenAsCookie(
      HttpServletRequest request, HttpServletResponse response, String idTokenString, int maxAge) {
    Cookie idTokenCookie = new SimpleCookie(ID_TOKEN_COOKIE_TEMPLATE);
    idTokenCookie.setSameSite(SameSiteOptions.NONE);
    idTokenCookie.setValue(idTokenString);
    idTokenCookie.setHttpOnly(true);
    idTokenCookie.setMaxAge(maxAge);
    idTokenCookie.setPath(request.getContextPath());
    idTokenCookie.saveTo(request, response);
  }

  private void redirectToSavedRequest(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String savedUri = request.getParameter(STATE_PARAM);
    String loginUri = AadUtils.toAbsoluteUri(request, getLoginUrl());
    if (savedUri == null || savedUri.equals(loginUri)) {
      savedUri = getSuccessUrl();
    }

    WebUtils.issueRedirect(request, response, savedUri);
  }

  /**
   * Based on "Accept" header, if "text/html" is accepted redirects using {@code 302 Found} to
   * authorization endpoint of the identity provider, otherwise returns {@code 401 Unauthorized}
   *
   * @param httpRequest the {@link HttpServletRequest}
   * @param httpResponse the {@link HttpServletResponse}
   * @throws IOException an exception thrown if response can't be streamed back to the client
   */
  void sendChallengeOrRedirectToLogin(
      HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
    var acceptHeaderValue = httpRequest.getHeader("Accept");
    if (acceptHeaderValue == null) {
      sendChallenge(httpResponse);
      return;
    }

    List<MediaType> acceptedMediaTypes;
    try {
      acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeaderValue);
    } catch (InvalidMediaTypeException e) {
      sendChallenge(httpResponse);
      return;
    }

    for (MediaType acceptedMediaType : acceptedMediaTypes) {
      if (acceptedMediaType.includes(MediaType.TEXT_HTML)) {
        redirectToLogin(httpRequest, httpResponse);
        return;
      }
    }

    sendChallenge(httpResponse);
  }

  private void sendChallenge(HttpServletResponse response) {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    String authcHeader = format("Bearer realm=\"%s\"", realmName);
    response.setHeader("WWW-Authenticate", authcHeader);
  }

  @Override
  protected void redirectToLogin(ServletRequest request, ServletResponse response)
      throws IOException {
    HttpServletRequest httpRequest = toHttp(request);
    String state = saveCurrentRequest(httpRequest);
    redirectToLogin(request, response, state);
  }

  protected void redirectToLogin(ServletRequest request, ServletResponse response, String state)
      throws IOException {
    HttpServletRequest httpRequest = toHttp(request);
    HttpServletResponse httpResponse = toHttp(response);

    Cookie stateCookie = new SimpleCookie(STATE_COOKIE_TEMPLATE);
    markAsCrossSiteCookie(stateCookie, httpRequest.isSecure());
    stateCookie.setValue(state);
    stateCookie.saveTo(httpRequest, httpResponse);

    String nonce = UUID.randomUUID().toString();
    Cookie nonceCookie = new SimpleCookie(NONCE_COOKIE_TEMPLATE);
    markAsCrossSiteCookie(nonceCookie, httpRequest.isSecure());
    nonceCookie.setValue(nonce);
    nonceCookie.saveTo(httpRequest, httpResponse);

    Map<String, String> params = new HashMap<>();
    params.put("response_type", ID_TOKEN_PARAM);
    params.put("response_mode", "form_post");
    params.put("redirect_uri", toAbsoluteUri(httpRequest, getLoginUrl()));
    params.put("client_id", clientId);
    params.put("scope", "openid offline_access profile");
    params.put(STATE_PARAM, state);
    params.put(NONCE_PARAM, nonce);
    WebUtils.issueRedirect(
        request, response, format("%s/%s/oauth2/v2.0/authorize", authority, tenant), params);
  }

  void markAsCrossSiteCookie(Cookie cookie, boolean https) {
    cookie.setSameSite(SameSiteOptions.NONE);
    if (https) {
      cookie.setSecure(true);
    } else {
      LOG.warn(
          "Trying to mark cookie [{}] with SameSite=None on insecure connection. "
              + "Some browsers may not accept or send such a cookie!",
          cookie.getName());
    }
  }

  String saveCurrentRequest(HttpServletRequest request) {
    if (!request.getMethod().equalsIgnoreCase("GET")) {
      return toAbsoluteUri(request, "/");
    }

    StringBuffer urlBuf = request.getRequestURL();
    String queryString = request.getQueryString();
    urlBuf.append(queryString == null ? "" : queryString);
    return urlBuf.toString();
  }

  @Override
  protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String idToken = ID_TOKEN_COOKIE_TEMPLATE.readValue(httpRequest, null);
    return new BearerToken(idToken, request.getRemoteHost());
  }

  @Override
  protected boolean onLoginSuccess(
      AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response)
      throws Exception {
    String tokenParam = request.getParameter(TOKEN_PARAM);
    if (tokenParam == null) return true;

    HttpServletRequest httpRequest = toHttp(request);
    HttpServletResponse httpResponse = toHttp(response);
    if (TOKEN_PARAM_CHECK.equals(tokenParam)) {
      return handleTockenCheck(token, httpRequest, httpResponse);
    }

    if (TOKEN_PARAM_REFRESH.equals(tokenParam)) {
      return handleTokenRefresh(httpResponse, httpRequest);
    }

    return true;
  }

  private boolean handleTockenCheck(
      AuthenticationToken token, HttpServletRequest request, HttpServletResponse httpResponse)
      throws IOException, ParseException {
    String nextCheckParam = request.getParameter(NEXT_CHECK_MIN_PARAM);
    long nextCheckMin = 0;
    if (nextCheckParam != null) {
      try {
        nextCheckMin = Long.parseLong(nextCheckParam);
      } catch (NumberFormatException nfe) {
        httpResponse.sendError(
            SC_BAD_REQUEST,
            format(
                "[%s] parameter should be the number of minutes to the next check",
                NEXT_CHECK_MIN_PARAM));
        return false;
      }
    }

    String idToken = ((BearerToken) token).getToken();
    JWTClaimsSet claimsSet = JWTParser.parse(idToken).getJWTClaimsSet();
    ZonedDateTime expirationTime =
        ZonedDateTime.ofInstant(claimsSet.getExpirationTime().toInstant(), ZoneId.systemDefault());
    long expiresInMin = Duration.between(ZonedDateTime.now(), expirationTime).getSeconds() / 60;
    String message = expiresInMin < nextCheckMin ? TOKEN_PARAM_REFRESH : TOKEN_PARAM_CHECK;
    httpResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
    httpResponse.getWriter().print(format("{\"token\": \"%s\"}", message));
    httpResponse.setStatus(SC_OK);
    return false;
  }

  private boolean handleTokenRefresh(HttpServletResponse response, HttpServletRequest request)
      throws IOException {
    StringBuffer urlBuf = request.getRequestURL();
    String state = urlBuf.append(format("?%s=%s", TOKEN_PARAM, TOKEN_PARAM_CHECK)).toString();
    ID_TOKEN_COOKIE_TEMPLATE.removeFrom(request, response);
    redirectToLogin(request, response, state);
    return false;
  }

  @Override
  protected boolean onLoginFailure(
      AuthenticationToken token,
      AuthenticationException e,
      ServletRequest request,
      ServletResponse response) {

    HttpServletRequest httpRequest = toHttp(request);
    HttpServletResponse httpResponse = toHttp(response);

    ID_TOKEN_COOKIE_TEMPLATE.removeFrom(httpRequest, httpResponse);
    return false;
  }

  @Override
  public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception)
      throws Exception {
    Subject subject = SecurityUtils.getSubject();
    org.apache.shiro.mgt.SecurityManager securityManager = SecurityUtils.getSecurityManager();
    securityManager.logout(subject);
  }
}
