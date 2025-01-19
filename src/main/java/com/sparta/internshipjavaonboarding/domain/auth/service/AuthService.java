package com.sparta.internshipjavaonboarding.domain.auth.service;

import com.sparta.internshipjavaonboarding.common.jwt.TokenProvider;
import com.sparta.internshipjavaonboarding.domain.auth.dto.request.SigninRequestDto;
import com.sparta.internshipjavaonboarding.domain.auth.dto.request.SignupRequestDto;
import com.sparta.internshipjavaonboarding.domain.auth.dto.response.SigninResponseDto;
import com.sparta.internshipjavaonboarding.domain.auth.dto.response.SignupResponseDto;
import com.sparta.internshipjavaonboarding.domain.user.entity.User;
import com.sparta.internshipjavaonboarding.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;

    @Transactional
    public ResponseEntity<SignupResponseDto> signup(SignupRequestDto requestDto) {
        try {
            if (userRepository.existsByUsername(requestDto.getUsername())) {
                throw new RuntimeException("이미 가입되어 있는 유저입니다.");
            }

            User user = User.builder()
                    .username(requestDto.getUsername())
                    .password(passwordEncoder.encode(requestDto.getPassword()))
                    .nickname(requestDto.getNickname())
                    .build();

            userRepository.save(user);
            log.info("사용자가 성공적으로 저장되었습니다: {}", user.getUsername());

            SignupResponseDto responseDto = SignupResponseDto.builder()
                    .username(user.getUsername())
                    .nickname(user.getNickname())
                    .authorityName(user.getAuthority())
                    .build();

            return ResponseEntity.ok(responseDto);
        } catch (Exception e) {
            log.error("회원가입 중 오류 발생:", e);
            throw e;
        }
    }

    @Transactional
    public ResponseEntity<SigninResponseDto> signin(SigninRequestDto requestDto) {
        try {

            log.info("사용자 로그인 시도 중: {}", requestDto.getUsername());

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(requestDto.getUsername(), requestDto.getPassword());

            Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
            log.info("사용자 인증 성공: {}", requestDto.getUsername());

            String jwt = tokenProvider.createAccessToken(authentication);
            log.info("JWT 토큰이 성공적으로 생성되었습니다.");

            SigninResponseDto responseDto = SigninResponseDto.builder()
                    .token(jwt)
                    .build();

            return ResponseEntity.ok(responseDto);
        } catch (Exception e) {
            log.error("로그인 중 오류 발생: ", e);
            throw e;
        }
    }
}
