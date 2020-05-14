package com.github.morulay.shiro.session;

import static org.apache.shiro.util.StringUtils.hasText;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.support.DelegatingSubject;

/**
 * Stateless {@link Session Session} implementation that is backed entirely by a standard servlet
 * container {@link HttpServletRequest HttpServletRequest} instance. It does not interact with any
 * of Shiro's session-related components {@code SessionManager}, {@code SecurityManager}, etc, and
 * instead satisfies all method implementations by interacting with a servlet container provided
 * {@link HttpServletRequest HttpServletRequest} instance.
 */
public class CookieRunAsSession implements Session {

  private static final String HOST_SESSION_KEY =
      CookieRunAsSession.class.getName() + ".HOST_SESSION_KEY";

  /** Key used to store the run as principals stack */
  private static final String RUN_AS_PRINCIPALS_SESSION_KEY =
      DelegatingSubject.class.getName() + ".RUN_AS_PRINCIPALS_SESSION_KEY";

  private HttpServletRequest httpRequest = null;
  private HttpServletResponse httpResponse = null;

  private Date startTimestamp;
  private Date lastAccessTime;

  private CookieRunAsManager cookieRunAsManager;

  public CookieRunAsSession(
      HttpServletRequest httpRequest,
      HttpServletResponse httpResponse,
      String host,
      CookieRunAsManager cookieRunAsManager) {

    if (httpRequest == null) {
      String msg = "HttpSession constructor argument cannot be null.";
      throw new IllegalArgumentException(msg);
    }

    this.httpRequest = httpRequest;
    this.httpResponse = httpResponse;
    this.cookieRunAsManager = cookieRunAsManager;
    if (hasText(host)) {
      setHost(host);
    }

    startTimestamp = new Date();
    lastAccessTime = startTimestamp;
  }

  @Override
  public Serializable getId() {
    return UUID.randomUUID();
  }

  @Override
  public Date getStartTimestamp() {
    return startTimestamp;
  }

  @Override
  public Date getLastAccessTime() {
    return lastAccessTime;
  }

  @Override
  public long getTimeout() {
    // Session stops with the end of the request
    return 0;
  }

  @Override
  public void setTimeout(long maxIdleTimeInMillis) {
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
  public void touch() {
    lastAccessTime = new Date();
  }

  @Override
  public void stop() {
    // Session ends with the end of the request
  }

  @Override
  public Collection<Object> getAttributeKeys() {
    Enumeration<String> namesEnum = httpRequest.getAttributeNames();
    Collection<Object> keys = null;
    if (namesEnum != null) {
      keys = new ArrayList<>();
      while (namesEnum.hasMoreElements()) {
        keys.add(namesEnum.nextElement());
      }
    }
    return keys;
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
  public Object getAttribute(Object key) {
    Object attribute = httpRequest.getAttribute(assertString(key));
    return readRunAs(key, attribute);
  }

  private Object readRunAs(Object key, Object attribute) {
    if (attribute == null
        && RUN_AS_PRINCIPALS_SESSION_KEY.equals(key)
        && cookieRunAsManager.isRunAs(httpRequest, httpResponse)) {
      attribute = cookieRunAsManager.readRunAs(httpRequest, httpResponse);
      httpRequest.setAttribute(RUN_AS_PRINCIPALS_SESSION_KEY, attribute);
    }

    return attribute;
  }

  @Override
  public void setAttribute(Object key, Object value) {
    httpRequest.setAttribute(assertString(key), value);
    storeRunAs(key, value);
  }

  @SuppressWarnings("unchecked")
  private void storeRunAs(Object key, Object value) {
    if (RUN_AS_PRINCIPALS_SESSION_KEY.equals(key) && value != null) {
      cookieRunAsManager.storeRunAs((List<PrincipalCollection>) value, httpRequest, httpResponse);
    }
  }

  @Override
  public Object removeAttribute(Object key) {
    String sKey = assertString(key);
    Object removed = httpRequest.getAttribute(sKey);
    httpRequest.removeAttribute(sKey);
    removeRunAs(key);
    return removed;
  }

  private void removeRunAs(Object key) {
    if (RUN_AS_PRINCIPALS_SESSION_KEY.equals(key)) {
      cookieRunAsManager.removeRunAs(httpRequest, httpResponse);
    }
  }
}
