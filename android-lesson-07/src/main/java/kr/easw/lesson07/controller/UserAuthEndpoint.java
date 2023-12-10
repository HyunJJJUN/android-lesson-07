package kr.easw.lesson07.controller;


import jakarta.servlet.http.HttpServletResponse;
import kr.easw.lesson07.model.ExceptionalResultDto;
import kr.easw.lesson07.model.UserDataEntity;
import kr.easw.lesson07.service.UserDataService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class UserAuthEndpoint {
    private final UserDataService userDataService;
    private final BCryptPasswordEncoder encoder;


    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody UserDataEntity entity) {
        try {
            return ResponseEntity.ok(userDataService.createTokenWith(entity));
        } catch (Exception ex) {
            return ResponseEntity.badRequest().body(new ExceptionalResultDto(ex.getMessage()));
        }
    }


    @PostMapping("/register")
    public void register(@ModelAttribute UserDataEntity entity , HttpServletResponse response) throws IOException {
        entity.setPassword(encoder.encode(entity.getPassword()));
        userDataService.createUser(entity);
        response.sendRedirect("/");
    }
}