package kr.easw.lesson07.service;

import kr.easw.lesson07.model.RemoveUserDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserDataEndPoint {

    private final UserDataService userDataService;

    @GetMapping("/list")
    public List<String> listUsers() {
        return userDataService.userList();
    }

    @PostMapping("/remove")
    public ResponseEntity<String> removeUser(@RequestBody RemoveUserDto removeUser) {
        userDataService.deleteUser(removeUser.getUserId());
        return ResponseEntity.ok().body(removeUser.getUserId());
    }

}