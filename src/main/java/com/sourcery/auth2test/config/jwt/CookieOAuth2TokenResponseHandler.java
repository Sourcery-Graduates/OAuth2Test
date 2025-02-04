package com.sourcery.auth2test.config.jwt;

import java.util.Objects;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.HashMap;
import org.springframework.http.MediaType;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class CookieOAuth2TokenResponseHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException {

        OAuth2AccessTokenAuthenticationToken tokenAuthentication =
            (OAuth2AccessTokenAuthenticationToken) authentication;

        // Установка refresh token в cookie
        if (tokenAuthentication.getRefreshToken() != null) {
            Cookie refreshTokenCookie = new Cookie("refresh_token",
                tokenAuthentication.getRefreshToken().getTokenValue());
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(false); // TODO - NOT FOR PRODUCTION - !must be secure!
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge((int) Duration.between(Instant.now(),
                tokenAuthentication.getRefreshToken().getExpiresAt()).getSeconds());
            response.addCookie(refreshTokenCookie);
        }

        // Отправка access и id tokens в теле
        Map<String, Object> tokens = new HashMap<>();
        tokens.put("access_token", tokenAuthentication.getAccessToken().getTokenValue());
        tokens.put("token_type", tokenAuthentication.getAccessToken().getTokenType().getValue());
        tokens.put("expires_in", Duration.between(Instant.now(),
            tokenAuthentication.getAccessToken().getExpiresAt()).getSeconds());

        if (tokenAuthentication.getAdditionalParameters().get("id_token") != null) {
            tokens.put("id_token", tokenAuthentication.getAdditionalParameters().get("id_token"));
        }

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getWriter(), tokens);
    }
}
