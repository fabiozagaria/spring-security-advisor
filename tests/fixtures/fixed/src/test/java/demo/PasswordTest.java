package demo;

import org.springframework.security.crypto.password.NoOpPasswordEncoder;

class PasswordTest {
    Object encoder = NoOpPasswordEncoder.getInstance();
}
