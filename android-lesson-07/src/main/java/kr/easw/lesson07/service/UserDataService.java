package kr.easw.lesson07.service;

import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;
import kr.easw.lesson07.Repository.UserDataRepository;
import kr.easw.lesson07.model.UserAuthenticationDto;
import kr.easw.lesson07.model.UserDataEntity;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserDataService {
    private final UserDataRepository repository;
    private final BCryptPasswordEncoder encoder;
    private final JwtService jwtService;

    @PostConstruct
    public void init() {
        System.out.println("Creating admin user");
        createUser(new UserDataEntity(0L, "admin", encoder.encode("admin"), true));
        createUser(new UserDataEntity(0L, "guest", encoder.encode("guest"), false));
    }

    public boolean isUserExists(String userId) {
        return repository.findUserDataEntityByUserId(userId).isPresent();
    }

    public void createUser(UserDataEntity entity) {
        repository.save(entity);
    }

    @Nullable
    public UserAuthenticationDto createTokenWith(UserDataEntity userDataEntity) {
        Optional<UserDataEntity> entity = repository.findUserDataEntityByUserId(userDataEntity.getUserId());
        if (entity.isEmpty()) throw new BadCredentialsException("Credentials invalid");
        UserDataEntity archivedEntity = entity.get();
        if (encoder.matches(userDataEntity.getPassword(), archivedEntity.getPassword()))
            return new UserAuthenticationDto(jwtService.generateToken(archivedEntity.getUserId()));
        throw new BadCredentialsException("Credentials invalid");
    }

    public List<String> userList() {
        List<UserDataEntity> all = repository.findAll();
        List<String> userIdList = new ArrayList<>();
        for (UserDataEntity userDataEntity : all) {
            userIdList.add(userDataEntity.getUserId());
        }
        return userIdList;
    }

    public void deleteUser(String userId) {
        Optional<UserDataEntity> entity = repository.findUserDataEntityByUserId(userId);
        UserDataEntity userDataEntity = entity.get();
        repository.delete(userDataEntity);
    }
}