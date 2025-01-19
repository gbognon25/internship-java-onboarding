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

class RefreshTokenProviderTest {

    private TokenProvider tokenProvider;
    private JwtProperties jwtProperties;
    private Authentication authentication;

    private final String secretKey = "dGVzdC1zZWNyZXQta2V5LWZvci1qd3QtdG9rZW4tdGVzdGluZy1zcHJpbmctYm9vdC1pbnRlcm5zaGlwLWFzc2lnbm1lbnQtd2l0aC1qd3QtYW5kLXNwcmluZy1zZWN1cml0eS10ZXN0aW5n";
    private final Long accessTokenValidityInSeconds = 3600L;
    private final Long refreshTokenValidityInSeconds = 604800L; // 7 days

    @BeforeEach
    void setUp() {
        // Given
        jwtProperties = new JwtProperties();
        jwtProperties.setSecret(secretKey);
        jwtProperties.setAccessTokenValidityInSeconds(accessTokenValidityInSeconds);
        jwtProperties.setRefreshTokenValidityInSeconds(refreshTokenValidityInSeconds);

        tokenProvider = new TokenProvider(jwtProperties);

        User user = new User("testUser", "password",
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        authentication = new UsernamePasswordAuthenticationToken(user, "password", user.getAuthorities());
    }

    @Nested
    @DisplayName("리프레시 토큰 생성 테스트")
    class RefreshTokenGenerationTest {

        @Test
        @DisplayName("사용자 인증으로 유효한 리프레시 토큰을 생성해야 한다")
        void shouldGenerateValidRefreshToken() {
            // When
            String token = tokenProvider.createRefreshToken(authentication);

            // Then
            assertNotNull(token);
            assertTrue(tokenProvider.validateToken(token));
        }

        @Test
        @DisplayName("액세스 토큰과 리프레시 토큰이 서로 달라야 한다")
        void shouldGenerateDifferentTokens() {
            // When
            String accessToken = tokenProvider.createAccessToken(authentication);
            String refreshToken = tokenProvider.createRefreshToken(authentication);

            // Then
            assertNotEquals(accessToken, refreshToken);
        }

        @Test
        @DisplayName("리프레시 토큰의 만료 시간이 액세스 토큰보다 길어야 한다")
        void shouldHaveLongerExpirationThanAccessToken() {
            // Given
            jwtProperties.setRefreshTokenValidityInSeconds(604800L); // 7 days
            TokenProvider tokenProvider = new TokenProvider(jwtProperties);

            // When
            String accessToken = tokenProvider.createAccessToken(authentication);
            String refreshToken = tokenProvider.createRefreshToken(authentication);

            Claims accessTokenClaims = Jwts.parserBuilder()
                    .setSigningKey(tokenProvider.getKey())
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();

            Claims refreshTokenClaims = Jwts.parserBuilder()
                    .setSigningKey(tokenProvider.getKey())
                    .build()
                    .parseClaimsJws(refreshToken)
                    .getBody();

            long accessTokenExpiration = accessTokenClaims.getExpiration().getTime();
            long refreshTokenExpiration = refreshTokenClaims.getExpiration().getTime();

            // Then
            assertTrue(refreshTokenExpiration > accessTokenExpiration);
        }
    }

    @Nested
    @DisplayName("리프레시 토큰 검증 테스트")
    class RefreshTokenValidationTest {

        @Test
        @DisplayName("올바르게 형식화된 리프레시 토큰을 성공적으로 검증해야 한다")
        void shouldValidateProperRefreshToken() {
            // When
            String token = tokenProvider.createRefreshToken(authentication);

            // Then
            assertTrue(tokenProvider.validateToken(token));
        }

        @Test
        @DisplayName("만료된 리프레시 토큰을 거부해야 한다")
        void shouldRejectExpiredRefreshToken() {
            // Given
            jwtProperties.setRefreshTokenValidityInSeconds(0L); // 만료 시간을 0초로 설정
            TokenProvider shortLivedTokenProvider = new TokenProvider(jwtProperties);

            // When
            String token = shortLivedTokenProvider.createRefreshToken(authentication);

            // Then
            assertFalse(shortLivedTokenProvider.validateToken(token));
        }

        @Test
        @DisplayName("잘못된 형식의 리프레시 토큰을 거부해야 한다")
        void shouldRejectMalformedRefreshToken() {
            // Given
            String malformedToken = "malformed.refresh.token.here";

            // Then
            assertFalse(tokenProvider.validateToken(malformedToken));
        }

        @Test
        @DisplayName("리프레시 토큰으로부터 올바른 사용자 정보를 추출해야 한다")
        void shouldExtractCorrectUserInfoFromRefreshToken() {
            // When
            String token = tokenProvider.createRefreshToken(authentication);
            Authentication resultAuth = tokenProvider.getAuthentication(token);

            // Then
            assertEquals("testUser", resultAuth.getName());
            assertThat(resultAuth.getAuthorities())
                    .extracting(GrantedAuthority::getAuthority)
                    .containsExactly("ROLE_USER");
        }
    }
}