package com.github.morulay.shiro.aad;

import static java.util.Objects.isNull;

import javax.servlet.http.HttpServletRequest;
import org.springframework.util.Assert;

public class AadUtils {

  private AadUtils() {}

  /**
   * Turns the given path to an absolute URI taking into account the context path
   *
   * @param request the current HTTP request
   * @param path a context path relative path
   * @return an absolute URI taking into account the context path
   */
  public static String toAbsoluteUri(final HttpServletRequest request, final String path) {
    Assert.notNull(request, "request is mandatory");
    String reqPath = request.getRequestURI();
    StringBuffer urlBuf = request.getRequestURL();
    urlBuf.setLength(urlBuf.length() - reqPath.length());
    urlBuf.append(request.getContextPath());

    if (isNull(path) || path.isEmpty()) {
      return urlBuf.toString();
    }

    urlBuf.append(path.startsWith("/") ? "" : "/");
    urlBuf.append(path);
    return urlBuf.toString();
  }
}
