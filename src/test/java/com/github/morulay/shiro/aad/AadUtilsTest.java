package com.github.morulay.shiro.aad;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AadUtilsTest {

  @Mock private HttpServletRequest request;

  @Test
  void testToAbsoluteUri() {
    when(request.getRequestURI()).thenReturn("/ctx/test");
    when(request.getRequestURL()).thenReturn(new StringBuffer("https://localhost:8080/ctx/test"));
    when(request.getContextPath()).thenReturn("/ctx");
    String result = AadUtils.toAbsoluteUri(request, "path");
    assertThat(result).isEqualTo("https://localhost:8080/ctx/path");
  }
}
