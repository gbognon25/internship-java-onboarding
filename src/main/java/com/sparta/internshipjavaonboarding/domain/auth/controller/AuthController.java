package com.sparta.internshipjavaonboarding.domain.auth.controller;

import com.sparta.internshipjavaonboarding.domain.auth.dto.request.SigninRequestDto;
import com.sparta.internshipjavaonboarding.domain.auth.dto.request.SignupRequestDto;
import com.sparta.internshipjavaonboarding.domain.auth.dto.response.SigninResponseDto;
import com.sparta.internshipjavaonboarding.domain.auth.dto.response.SignupResponseDto;
import com.sparta.internshipjavaonboarding.domain.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponseDto> signup(@RequestBody SignupRequestDto requestDto) {
        log.debug("사용자에 대한 회원가입 요청이 접수되었습니다: {}", requestDto.getUsername());
        return authService.signup(requestDto);
    }

    @PostMapping("/signin")
    public ResponseEntity<SigninResponseDto> signin(@RequestBody SigninRequestDto requestDto) {
        log.debug("사용자에 대한 로그인 요청이 접수되었습니다: {}", requestDto.getUsername());
        return authService.signin(requestDto);
    }
}
