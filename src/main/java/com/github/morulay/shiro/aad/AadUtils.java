package com.github.morulay.shiro.aad;

import javax.servlet.http.HttpServletRequest;

public class AadUtils {

  private AadUtils() {}

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
}
