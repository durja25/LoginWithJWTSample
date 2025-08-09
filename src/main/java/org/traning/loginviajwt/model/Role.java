package org.traning.loginviajwt.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.traning.loginviajwt.model.Permissions.*;

@RequiredArgsConstructor
public enum Role {

    USER(Collections.emptySet()),
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_UPDATE,
                    ADMIN_DELETE,
                    ADMIN_WRITE,
                    MANAGEMENT_READ,
                    MANAGEMENT_UPDATE,
                    MANAGEMENT_DELETE,
                    MANAGEMENT_WRITE
            )
    ),
    MANAGEMENT(
            Set.of(
                    MANAGEMENT_READ,
                    MANAGEMENT_UPDATE,
                    MANAGEMENT_DELETE,
                    MANAGEMENT_WRITE
            ));


    @Getter
    private final Set<Permissions> permissions;


    public List<SimpleGrantedAuthority> getAuthorities() {
        var authorities = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }

}
