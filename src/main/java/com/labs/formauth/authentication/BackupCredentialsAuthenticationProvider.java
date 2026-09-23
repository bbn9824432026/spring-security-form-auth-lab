package com.labs.formauth.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

// A second, completely independent credential source - a hardcoded
// "break-glass" account with nothing to do with the UserDetailsService.
// Exists purely to make the provider CHAIN itself observable.
public class BackupCredentialsAuthenticationProvider implements AuthenticationProvider {

    private static final String BREAK_GLASS_USER = "breakglass";
    private static final String BREAK_GLASS_PASS = "emergency123";

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        if (!BREAK_GLASS_USER.equals(username)) {
            // Not our account - ABSTAIN. Returning null tells ProviderManager
            // "not my concern, ask the next provider." This is the quiet path.
            System.out.println("[2.3] BackupProvider: '" + username + "' is not mine, abstaining (returning null)");
            return null;
        }

        if (!BREAK_GLASS_PASS.equals(password)) {
            // It WAS our username, but wrong password - this is a real failure,
            // not an abstain. Throwing here (not returning null) is what lets
            // this provider's exception potentially overwrite an earlier one.
            System.out.println("[2.3] BackupProvider: wrong break-glass password");
            throw new BadCredentialsException("Not a recognized break-glass account");
        }

        System.out.println("[2.3] BackupProvider: break-glass login succeeded");
        return UsernamePasswordAuthenticationToken.authenticated(
                username, password, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}