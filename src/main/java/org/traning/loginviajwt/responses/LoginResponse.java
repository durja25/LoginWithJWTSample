package org.traning.loginviajwt.responses;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter

public class LoginResponse {

    private String token;
    private Long expirationTime;

    public LoginResponse(String token, Long expirationTime) {
        this.token = token;
        this.expirationTime = expirationTime;
    }
}
