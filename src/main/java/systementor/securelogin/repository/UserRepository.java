package systementor.securelogin.repository;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import systementor.securelogin.model.UserModel;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserModel, Long> {
    Optional<UserModel> findByUsername(String username);

    @Modifying
    @Transactional
    @Query("update UserModel u set u.password = :newPassword where u.username = :username")
    void updatePassword(@Param("username") String username, @Param("newPassword") String newPassword);
}