package com.sparta.internshipjavaonboarding.common.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class TokenProviderTest {

    private TokenProvider tokenProvider;
    private JwtProperties jwtProperties;
    private Authentication authentication;

    // JWT의 테스트 비밀키
    private final String secretKey = "dGVzdC1zZWNyZXQta2V5LWZvci1qd3QtdG9rZW4tdGVzdGluZy1zcHJpbmctYm9vdC1pbnRlcm5zaGlwLWFzc2lnbm1lbnQtd2l0aC1qd3QtYW5kLXNwcmluZy1zZWN1cml0eS10ZXN0aW5n";
    private final Long accessTokenValidityInSeconds = 3600L;

    @BeforeEach
    void setUp() {
        // Given
        jwtProperties = new JwtProperties();
        jwtProperties.setSecret(secretKey);
        jwtProperties.setAccessTokenValidityInSeconds(accessTokenValidityInSeconds);

        tokenProvider = new TokenProvider(jwtProperties);

        User user = new User("testUser", "password",
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        authentication = new UsernamePasswordAuthenticationToken(user, "password", user.getAuthorities());
    }

    @Nested
    @DisplayName("액세스 토큰 생성 테스트")
    class AccessTokenGenerationTest {

        @Test
        @DisplayName("사용자 인증으로 유효한 액세스 토큰을 생성해야 한다")
        void shouldGenerateValidAccessToken() {
            // When
            String token = tokenProvider.createAccessToken(authentication);

            // Then
            assertNotNull(token);
            assertTrue(tokenProvider.validateToken(token));
        }

        @Test
        @DisplayName("토큰에 올바른 사용자 권한이 포함되어야 한다")
        void shouldIncludeCorrectAuthorities() {
            // When
            String token = tokenProvider.createAccessToken(authentication);
            Authentication resultAuth = tokenProvider.getAuthentication(token);

            // Then
            assertThat(resultAuth.getAuthorities())
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("설정된 속성에 따라 올바른 만료 시간이 설정되어야 한다")
        void shouldSetCorrectExpirationTime() {
            // When
            String token = tokenProvider.createAccessToken(authentication);

            // Then
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(tokenProvider.getKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            long expirationTime = claims.getExpiration().getTime();
            long currentTime = System.currentTimeMillis();
            long expectedExpirationTime = currentTime + (jwtProperties.getAccessTokenValidityInSeconds() * 1000);

            // 작은 시간 차이 허용 (예: 10초)
            assertTrue(Math.abs(expectedExpirationTime - expirationTime) < 10000);
        }
    }

    @Nested
    @DisplayName("토큰 검증 테스트")
    class TokenValidationTest {

        @Test
        @DisplayName("올바르게 형식화된 토큰을 성공적으로 검증해야 한다")
        void shouldValidateProperToken() {
            // 실행
            String token = tokenProvider.createAccessToken(authentication);

            // 검증
            assertTrue(tokenProvider.validateToken(token));
        }

        @Test
        @DisplayName("만료된 토큰을 거부해야 한다")
        void shouldRejectExpiredToken() {
            // Given
            jwtProperties.setAccessTokenValidityInSeconds(0); // 만료 시간을 0초로 설정
            TokenProvider shortLivedTokenProvider = new TokenProvider(jwtProperties);

            // When
            String token = shortLivedTokenProvider.createAccessToken(authentication);

            // Then
            assertFalse(shortLivedTokenProvider.validateToken(token));
        }

        @Test
        @DisplayName("잘못된 형식의 토큰을 거부해야 한다")
        void shouldRejectMalformedToken() {
            // Given
            String malformedToken = "malformed.token.here";

            // Then
            assertFalse(tokenProvider.validateToken(malformedToken));
        }

        @Test
        @DisplayName("유효한 토큰에서 올바른 사용자 정보를 추출해야 한다")
        void shouldExtractCorrectUserInfo() {
            // When
            String token = tokenProvider.createAccessToken(authentication);
            Authentication resultAuth = tokenProvider.getAuthentication(token);

            // Then
            assertEquals("testUser", resultAuth.getName());
            assertThat(resultAuth.getAuthorities())
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactly("ROLE_USER");
        }
    }
}