package org.traning.loginviajwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.traning.loginviajwt.model.Token;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {

    Optional<Token> findByToken(String token);

    @Query("""
            SELECT t
            FROM Token t
            inner join t.user u on u.id = t.user.id
            WHERE u.id = :userId
            AND (t.expired = false AND t.revoked = false)
            """)
    List<Token> findAllValidTokenByUser(Long userId);


}
