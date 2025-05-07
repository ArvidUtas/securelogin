package systementor.securelogin.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptService {

    private final int MAX_ATTEMPT = 5;
    private final long BLOCK_TIME = TimeUnit.MINUTES.toMillis(15);

    private static class Attempt{
        int failedAttempts;
        long blockedAt;

        public Attempt(int failedAttempts, long blockedAt) {
            this.failedAttempts = failedAttempts;
            this.blockedAt = blockedAt;
        }
    }
}
