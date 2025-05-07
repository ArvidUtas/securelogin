package systementor.securelogin.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptService {

    private final int MAX_ATTEMPT = 5;
    private final long BLOCK_TIME = TimeUnit.MINUTES.toMillis(15);
    private ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();

    public void loginSuccess(String username){
        attempts.remove(username);
    }

    public void loginFailed(String username){
        Attempt userAttempt = attempts.getOrDefault(username, new Attempt(0,0));
        userAttempt.failedAttempts++;
        if (userAttempt.failedAttempts>= MAX_ATTEMPT){
            userAttempt.blockedAt = System.currentTimeMillis();
        }
        attempts.put(username, userAttempt);
    }

    public boolean isBlocked(String username){
        Attempt userAttempt = attempts.get(username);
        if (userAttempt == null || userAttempt.failedAttempts < MAX_ATTEMPT)
            return false;
        if (BLOCK_TIME < System.currentTimeMillis() - userAttempt.blockedAt){
            attempts.remove(username);
            return false;
        }
        return true;
    }

    private static class Attempt{
        int failedAttempts;
        long blockedAt;

        public Attempt(int failedAttempts, long blockedAt) {
            this.failedAttempts = failedAttempts;
            this.blockedAt = blockedAt;
        }
    }
}
