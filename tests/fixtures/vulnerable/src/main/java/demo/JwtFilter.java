package demo;

import org.springframework.web.filter.OncePerRequestFilter;

public class JwtFilter extends OncePerRequestFilter {
    private static final String PREFIX = "Bearer ";
}
