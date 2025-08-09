package org.traning.loginviajwt.dto;

import lombok.Getter;
import lombok.Setter;
import org.traning.loginviajwt.model.Role;

@Getter
@Setter
public class RegisterUserDto {
    private String email;
    private String password;
    private String username;
    private Role role;



}
