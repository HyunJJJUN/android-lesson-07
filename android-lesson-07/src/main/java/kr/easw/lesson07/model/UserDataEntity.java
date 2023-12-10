package kr.easw.lesson07.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Setter
public class UserDataEntity {
    @Id
    @GeneratedValue
    private long id;

    @Getter
    private String userId;

    @Getter
    private String password;

    @Getter
    private boolean isAdmin;

}