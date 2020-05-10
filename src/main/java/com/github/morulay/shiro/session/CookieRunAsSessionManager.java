package com.github.morulay.shiro.session;

import static org.apache.shiro.web.util.WebUtils.getHttpRequest;
import static org.apache.shiro.web.util.WebUtils.getHttpResponse;
import static org.apache.shiro.web.util.WebUtils.getRequest;
import static org.apache.shiro.web.util.WebUtils.isHttp;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.apache.shiro.web.util.WebUtils;

/**
 * SessionManager implementation providing {@link Session} implementations that are merely wrappers
 * for the Servlet container's {@link HttpServletRequest}.
 *
 * <p>Despite its name, this implementation <em>does not</em> itself manage Sessions since the
 * Servlet container provides the actual management support. This class mainly exists to
 * 'impersonate' a regular Shiro {@code SessionManager} so it can be pluggable into a normal Shiro
 * configuration in a pure web application.
 *
 * <p>Note that because this implementation relies on the {@link HttpServletRequest}, it is only
 * functional in a servlet container - it is not capable of supporting Sessions for any clients
 * other than those using the HTTP protocol.
 */
public class CookieRunAsSessionManager implements WebSessionManager {

  private CookieRunAsManager cookieRunAsManager;

  public CookieRunAsSessionManager(CookieRunAsManager cookieRunAsManager) {
    this.cookieRunAsManager = cookieRunAsManager;
  }

  @Override
  public Session start(SessionContext context) {
    return createSession(context);
  }

  @Override
  public Session getSession(SessionKey key) {
    if (!WebUtils.isHttp(key)) {
      String msg = "SessionKey must be an HTTP compatible implementation.";
      throw new IllegalArgumentException(msg);
    }

    HttpServletRequest request = getHttpRequest(key);
    HttpServletResponse response = getHttpResponse(key);
    return createSession(request, response, request.getRemoteHost());
  }

  protected Session createSession(
      HttpServletRequest request, HttpServletResponse response, String host) {
    return new CookieRunAsSession(request, response, host, cookieRunAsManager);
  }

  protected Session createSession(SessionContext sessionContext) {
    if (!isHttp(sessionContext)) {
      String msg = "SessionContext must be an HTTP compatible implementation.";
      throw new IllegalArgumentException(msg);
    }

    HttpServletRequest request = getHttpRequest(sessionContext);
    HttpServletResponse response = getHttpResponse(sessionContext);
    String host = getHost(sessionContext);
    return createSession(request, response, host);
  }

  private String getHost(SessionContext context) {
    String host = context.getHost();
    if (host == null) {
      ServletRequest request = getRequest(context);
      if (request != null) {
        host = request.getRemoteHost();
      }
    }

    return host;
  }

  /**
   * This implementation always delegates to the servlet container for sessions, so this method
   * returns {@code true} always.
   *
   * @return {@code true} always
   * @since 1.2
   */
  @Override
  public boolean isServletContainerSessions() {
    return true;
  }
}
