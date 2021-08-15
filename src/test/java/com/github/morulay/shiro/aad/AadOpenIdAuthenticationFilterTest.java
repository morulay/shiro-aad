package com.github.morulay.shiro.aad;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.AdditionalAnswers;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AadOpenIdAuthenticationFilterTest {

  @Spy
  private AadOpenIdAuthenticationFilter aadFilter =
      new AadOpenIdAuthenticationFilter("authority", "tenant", "/login", "123456", "realm");

  @Mock private HttpServletRequest request;

  @Mock HttpServletResponse response;

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"ala-bala", "application/json;image/png"})
  void testSendChallengeOrRedirectToLogin_nonHtmlAcceptHeader(String acceptHeaderValue)
      throws IOException {
    when(request.getHeader(eq("Accept"))).thenReturn(acceptHeaderValue);
    aadFilter.sendChallengeOrRedirectToLogin(request, response);
    verify(response).setStatus(eq(HttpServletResponse.SC_UNAUTHORIZED));
    verify(response).setHeader(eq("WWW-Authenticate"), anyString());
  }

  @Test
  void testSendChallengeOrRedirectToLogin_htmlAcceptHeader() throws IOException {
    when(request.getHeader(eq("Accept"))).thenReturn("text/html");
    when(request.getMethod()).thenReturn("GET");
    when(request.getRequestURI()).thenReturn("/index.html");
    when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/index.html"));
    when(response.encodeRedirectURL(anyString())).then(AdditionalAnswers.returnsFirstArg());
    aadFilter.sendChallengeOrRedirectToLogin(request, response);
    verify(response).sendRedirect(anyString());
  }
}
