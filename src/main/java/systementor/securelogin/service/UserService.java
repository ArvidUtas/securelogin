package systementor.securelogin.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;
import systementor.securelogin.model.UserModel;
import systementor.securelogin.repository.UserRepository;

import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public void registerUser(String username, String password){
        UserModel userModel = new UserModel();
        userModel.setUsername(username);
        userModel.setPassword(BCrypt.hashpw(password, BCrypt.gensalt()));
        userRepository.save(userModel);
    }

    public void updatePassword(String username, String password, String newPassword){
        userRepository.updatePassword(username, BCrypt.hashpw(newPassword, BCrypt.gensalt()));
    }

    public Optional<String> findByUsername(String username) {
        return userRepository.findByUsername(username).map(UserModel::getPassword);
    }

    public boolean userIsRegistered(String username) {
        return userRepository.findByUsername(username).isPresent();
    }
}