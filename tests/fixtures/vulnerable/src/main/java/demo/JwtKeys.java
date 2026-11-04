package demo;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class JwtKeys {
    SecretKey key() {
        return new SecretKeySpec("changeit".getBytes(), "HmacSHA256");
    }
}
