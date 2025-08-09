package org.traning.loginviajwt.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permissions {

    ADMIN_READ("admin:read"),
    ADMIN_WRITE("admin:write"),
    ADMIN_DELETE("admin:delete"),
    ADMIN_UPDATE("admin:update"),

    MANAGEMENT_READ("management:read"),
    MANAGEMENT_WRITE("management:write"),
    MANAGEMENT_DELETE("management:delete"),
    MANAGEMENT_UPDATE("management:update"),

    USER_READ("user:read"),
    USER_WRITE("user:write"),
    USER_DELETE("user:delete"),
    USER_UPDATE("user:update");


    @Getter
    private final String permission;
}
