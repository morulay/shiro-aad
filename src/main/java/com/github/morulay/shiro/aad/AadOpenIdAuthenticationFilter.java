package com.github.morulay.shiro.aad;

import static java.lang.String.format;
import static java.util.Map.entry;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import java.io.IOException;
import java.text.ParseException;
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
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.Cookie.SameSiteOptions;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AadOpenIdAuthenticationFilter extends AuthenticatingFilter {

  private static final String AUTH_ERROR_PARAM = "error";
  private static final String AUTH_CODE_PARAM = "code";
  private static final String ID_TOKEN_PARAM = "id_token";
  private static final String STATE_PARAM = "state";
  private static final String NONCE_PARAM = "nonce";

  private static final SimpleCookie ID_TOKEN_COOKIE_TEMPLATE = new SimpleCookie(ID_TOKEN_PARAM);
  private static final SimpleCookie STATE_COOKIE_TEMPLATE = new SimpleCookie(STATE_PARAM);
  private static final SimpleCookie NONCE_COOKIE_TEMPLATE = new SimpleCookie(NONCE_PARAM);

  private static final Logger LOG = LoggerFactory.getLogger(AadOpenIdAuthenticationFilter.class);

  private String authority;
  private String tenant;
  private String clientId;

  public AadOpenIdAuthenticationFilter(
      String authority,
      String tenant,
      String redirectUri,
      String clientId,
      String unauthorizedUrl) {
    this.authority = authority;
    this.tenant = tenant;
    setLoginUrl(redirectUri);
    this.clientId = clientId;
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

    redirectToLogin(httpRequest, httpResponse);
    return false;
  }

  private boolean hasAccessToken(HttpServletRequest request) {
    return ID_TOKEN_COOKIE_TEMPLATE.readValue(request, null) != null;
  }

  @Override
  protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
    HttpServletRequest httpRequest = WebUtils.toHttp(request);
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
      HttpServletRequest request, HttpServletResponse response) throws Exception {

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
      throw new AuthenticationException("Invalid OpenID Connect token");
    }

    AuthenticationSuccessResponse oidcResponse = (AuthenticationSuccessResponse) authResponse;
    validateScope(oidcResponse);
    validateNonce(NONCE_COOKIE_TEMPLATE.readValue(request, response), oidcResponse);
    removeScopeAndNonceCookies(request, response);

    storeIdTokenAsCookie(request, response, oidcResponse.getIDToken().getParsedString());
    redirectToSavedRequest(request, response);
  }

  private void validateState(String stateCookie, String state) throws Exception {
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
      throw new AuthenticationException("Invalid OpenID Connect token");
    }

    if (!Objects.equals(nonceCookie, nonce)) {
      LOG.warn(
          "Authentication response nonce [{}] differs from stored one [{}]", nonce, nonceCookie);
      throw new AuthenticationException("Invalid OpenID Connect token");
    }
  }

  private void removeScopeAndNonceCookies(
      HttpServletRequest request, HttpServletResponse response) {
    STATE_COOKIE_TEMPLATE.removeFrom(request, response);
    NONCE_COOKIE_TEMPLATE.removeFrom(request, response);
  }

  private void storeIdTokenAsCookie(
      HttpServletRequest request, HttpServletResponse response, String idTokenString) {
    Cookie idTokenCookie = new SimpleCookie(ID_TOKEN_COOKIE_TEMPLATE);
    idTokenCookie.setValue(idTokenString);
    idTokenCookie.setHttpOnly(true);
    // accessTokenCookie.setSecure(true);
    idTokenCookie.setMaxAge(30 * 60);
    idTokenCookie.setPath(request.getContextPath());
    idTokenCookie.saveTo(request, response);
  }

  private void redirectToSavedRequest(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String savedUri = request.getParameter(STATE_PARAM);
    WebUtils.issueRedirect(request, response, savedUri);
  }

  @Override
  protected void redirectToLogin(ServletRequest request, ServletResponse response)
      throws IOException {
    HttpServletRequest httpRequest = WebUtils.toHttp(request);
    HttpServletResponse httpResponse = WebUtils.toHttp(response);

    String state = saveCurrentRequest(httpRequest);
    Cookie stateCookie = new SimpleCookie(STATE_COOKIE_TEMPLATE);
    stateCookie.setValue(state);
    stateCookie.setSameSite(SameSiteOptions.NONE);
    stateCookie.saveTo(httpRequest, httpResponse);

    String nonce = UUID.randomUUID().toString();
    Cookie nonceCookie = new SimpleCookie(NONCE_COOKIE_TEMPLATE);
    nonceCookie.setValue(nonce);
    nonceCookie.setSameSite(SameSiteOptions.NONE);
    nonceCookie.saveTo(httpRequest, httpResponse);

    Map<String, String> params =
        Map.ofEntries(
            entry("response_type", ID_TOKEN_PARAM),
            entry("response_mode", "form_post"),
            entry("redirect_uri", toAbsoluteUri(httpRequest, getLoginUrl())),
            entry("client_id", clientId),
            entry("scope", "openid offline_access profile"),
            entry(STATE_PARAM, state),
            entry(NONCE_PARAM, nonce));
    WebUtils.issueRedirect(
        request, response, format("%s/%s/oauth2/v2.0/authorize", authority, tenant), params);
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

  /**
   * Turns the given path to an absolute URI taking into account the context path
   *
   * @param request the current HTTP request
   * @param path a context path relative path
   * @return an absolute URI taking into account the context path
   */
  public static String toAbsoluteUri(HttpServletRequest request, String path) {
    String reqPath = request.getRequestURI();
    StringBuffer urlBuf = request.getRequestURL();
    urlBuf.setLength(urlBuf.length() - reqPath.length());
    urlBuf.append(request.getContextPath());
    urlBuf.append(path.length() == 0 || path.startsWith("/") ? "" : "/");
    urlBuf.append(path);
    return urlBuf.toString();
  }

  @Override
  protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String idToken = ID_TOKEN_COOKIE_TEMPLATE.readValue(httpRequest, null);
    return new OpenIdToken(idToken, request.getRemoteHost());
  }

  @Override
  protected boolean onLoginFailure(
      AuthenticationToken token,
      AuthenticationException e,
      ServletRequest request,
      ServletResponse response) {

    HttpServletRequest httpRequest = WebUtils.toHttp(request);
    HttpServletResponse httpResponse = WebUtils.toHttp(response);

    ID_TOKEN_COOKIE_TEMPLATE.removeFrom(httpRequest, httpResponse);
    return false;
  }

  @Override
  public void afterCompletion(ServletRequest request, ServletResponse response, Exception exception)
      throws Exception {
    Subject subject = SecurityUtils.getSubject();
    subject.logout();
  }
}
