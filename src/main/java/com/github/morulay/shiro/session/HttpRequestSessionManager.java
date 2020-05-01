package com.github.morulay.shiro.session;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
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
public class HttpRequestSessionManager implements WebSessionManager {

  public HttpRequestSessionManager() {}

  @Override
  public Session start(SessionContext context) throws AuthorizationException {
    return createSession(context);
  }

  @Override
  public Session getSession(SessionKey key) throws SessionException {
    if (!WebUtils.isHttp(key)) {
      String msg = "SessionKey must be an HTTP compatible implementation.";
      throw new IllegalArgumentException(msg);
    }

    HttpServletRequest request = WebUtils.getHttpRequest(key);
    return createSession(request, request.getRemoteHost());
  }

  private String getHost(SessionContext context) {
    String host = context.getHost();
    if (host == null) {
      ServletRequest request = WebUtils.getRequest(context);
      if (request != null) {
        host = request.getRemoteHost();
      }
    }
    return host;
  }

  protected Session createSession(SessionContext sessionContext) throws AuthorizationException {
    if (!WebUtils.isHttp(sessionContext)) {
      String msg = "SessionContext must be an HTTP compatible implementation.";
      throw new IllegalArgumentException(msg);
    }

    HttpServletRequest request = WebUtils.getHttpRequest(sessionContext);
    String host = getHost(sessionContext);
    return createSession(request, host);
  }

  protected Session createSession(HttpServletRequest request, String host) {
    return new HttpRequestSession(request, host);
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
