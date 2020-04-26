package com.github.morulay.shiro.session;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.util.StringUtils;
import org.apache.shiro.web.servlet.ShiroHttpSession;

/**
 * Stateless {@link Session Session} implementation that is backed entirely by a standard servlet
 * container {@link HttpServletRequest HttpServletRequest} instance. It does not interact with any
 * of Shiro's session-related components {@code SessionManager}, {@code SecurityManager}, etc, and
 * instead satisfies all method implementations by interacting with a servlet container provided
 * {@link HttpServletRequest HttpServletRequest} instance.
 *
 */
public class HttpRequestSession implements Session {

  private static final String HOST_SESSION_KEY =
      HttpRequestSession.class.getName() + ".HOST_SESSION_KEY";
  private static final String TOUCH_OBJECT_SESSION_KEY =
      HttpRequestSession.class.getName() + ".TOUCH_OBJECT_SESSION_KEY";

  private HttpServletRequest httpSession = null;

  public HttpRequestSession(HttpServletRequest httpSession, String host) {
    if (httpSession == null) {
      String msg = "HttpSession constructor argument cannot be null.";
      throw new IllegalArgumentException(msg);
    }
    if (httpSession instanceof ShiroHttpSession) {
      String msg =
          "HttpSession constructor argument cannot be an instance of ShiroHttpSession.  This "
              + "is enforced to prevent circular dependencies and infinite loops.";
      throw new IllegalArgumentException(msg);
    }
    this.httpSession = httpSession;
    if (StringUtils.hasText(host)) {
      setHost(host);
    }
  }

  @Override
  public Serializable getId() {
    return UUID.randomUUID();
  }

  @Override
  public Date getStartTimestamp() {
    return new Date();
  }

  @Override
  public Date getLastAccessTime() {
    return new Date();
  }

  @Override
  public long getTimeout() throws InvalidSessionException {
    // Session stops with the end of the request
    return 0;
  }

  @Override
  public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
    // Session ends with the end of the request
  }

  protected void setHost(String host) {
    setAttribute(HOST_SESSION_KEY, host);
  }

  @Override
  public String getHost() {
    return (String) getAttribute(HOST_SESSION_KEY);
  }

  @Override
  public void touch() throws InvalidSessionException {
    // just manipulate the session to update the access time:
    try {
      httpSession.setAttribute(TOUCH_OBJECT_SESSION_KEY, TOUCH_OBJECT_SESSION_KEY);
      httpSession.removeAttribute(TOUCH_OBJECT_SESSION_KEY);
    } catch (Exception e) {
      throw new InvalidSessionException(e);
    }
  }

  @Override
  public void stop() throws InvalidSessionException {
    // Session ends with the end of the request
  }

  @Override
  public Collection<Object> getAttributeKeys() throws InvalidSessionException {
    try {
      Enumeration<String> namesEnum = httpSession.getAttributeNames();
      Collection<Object> keys = null;
      if (namesEnum != null) {
        keys = new ArrayList<Object>();
        while (namesEnum.hasMoreElements()) {
          keys.add(namesEnum.nextElement());
        }
      }
      return keys;
    } catch (Exception e) {
      throw new InvalidSessionException(e);
    }
  }

  private static String assertString(Object key) {
    if (!(key instanceof String)) {
      String msg =
          "HttpSession based implementations of the Shiro Session interface requires attribute keys "
              + "to be String objects.  The HttpSession class does not support anything other than String keys.";
      throw new IllegalArgumentException(msg);
    }
    return (String) key;
  }

  @Override
  public Object getAttribute(Object key) throws InvalidSessionException {
    try {
      return httpSession.getAttribute(assertString(key));
    } catch (Exception e) {
      throw new InvalidSessionException(e);
    }
  }

  @Override
  public void setAttribute(Object key, Object value) throws InvalidSessionException {
    try {
      httpSession.setAttribute(assertString(key), value);
    } catch (Exception e) {
      throw new InvalidSessionException(e);
    }
  }

  @Override
  public Object removeAttribute(Object key) throws InvalidSessionException {
    try {
      String sKey = assertString(key);
      Object removed = httpSession.getAttribute(sKey);
      httpSession.removeAttribute(sKey);
      return removed;
    } catch (Exception e) {
      throw new InvalidSessionException(e);
    }
  }
}
