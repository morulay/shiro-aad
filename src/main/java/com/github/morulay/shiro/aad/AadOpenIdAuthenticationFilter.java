package com.github.morulay.shiro.aad;

import static com.github.morulay.shiro.aad.AadUtils.toAbsoluteUri;
import static java.lang.String.format;
import static org.apache.shiro.web.util.WebUtils.toHttp;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
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
public class AadOpenIdAuthenticationFilter extends AuthenticatingFilter {

  private static final String AUTH_ERROR_PARAM = "error";
  private static final String AUTH_CODE_PARAM = "code";
  private static final String ID_TOKEN_PARAM = "id_token";
  private static final String STATE_PARAM = "state";
  private static final String NONCE_PARAM = "nonce";

  static final SimpleCookie ID_TOKEN_COOKIE_TEMPLATE = new SimpleCookie(ID_TOKEN_PARAM);
  private static final SimpleCookie STATE_COOKIE_TEMPLATE = new SimpleCookie(STATE_PARAM);
  private static final SimpleCookie NONCE_COOKIE_TEMPLATE = new SimpleCookie(NONCE_PARAM);

  private static final Logger LOG = LoggerFactory.getLogger(AadOpenIdAuthenticationFilter.class);

  private String authority;
  private String tenant;
  private String clientId;
  private String realmName;
  private Set<String> noRedirectMimes;

  /**
   * @param authority the Microsoft authority instance base URI, e.g. {@code
   *     https://login.microsoftonline.com}
   * @param tenant the name of the tenant
   * @param redirectUri the URI where the identity provider will send the security tokens back to
   * @param clientId the ID assigned to your application by Azure AD when the application was
   *     registered
   * @param realmName the authorization realm name
   * @param noRedirectMimes the {@link Set} of MIME types for which the filter will return {@code
   *     401 Unauthorized} instead to redirect using {@code 302 Found} to authorization endpoint of
   *     identity provider. Default is {@code application/json}
   */
  public AadOpenIdAuthenticationFilter(
      String authority,
      String tenant,
      String redirectUri,
      String clientId,
      String realmName,
      Set<String> noRedirectMimes) {
    this.authority = authority;
    this.tenant = tenant;
    setLoginUrl(redirectUri);
    this.clientId = clientId;
    this.realmName = realmName;
    this.noRedirectMimes = noRedirectMimes;
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

  private void sendChallengeOrRedirectToLogin(
      HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException {
    if (noRedirectMimes != null && noRedirectMimes.size() > 0) {
      Enumeration<String> accepts = httpRequest.getHeaders("Accept");
      while (accepts.hasMoreElements()) {
        String mime = accepts.nextElement().toLowerCase();
        if (noRedirectMimes.contains(mime)) {
          sendChallenge(httpRequest, httpResponse);
          return;
        }
      }
    }

    redirectToLogin(httpRequest, httpResponse);
  }

  private void sendChallenge(HttpServletRequest ignore, HttpServletResponse response) {
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    String authcHeader = format("Bearer realm=\"%s\"", realmName);
    response.setHeader("WWW-Authenticate", authcHeader);
  }

  @Override
  protected void redirectToLogin(ServletRequest request, ServletResponse response)
      throws IOException {
    HttpServletRequest httpRequest = toHttp(request);
    HttpServletResponse httpResponse = toHttp(response);

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
    return new OpenIdToken(idToken, request.getRemoteHost());
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
    subject.logout();
  }
}
