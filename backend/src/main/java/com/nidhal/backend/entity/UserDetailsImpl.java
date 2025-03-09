package com.nidhal.backend.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public record UserDetailsImpl(User user) implements UserDetails {

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return user.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        // initialize a set of authorities
        Set<GrantedAuthority> authorities = new HashSet<>();

        String role = String.valueOf(user.getRole());

        // transform the user's role to a simple granted authority
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(role);

        // add the simple granted authority to the set of authorities
        authorities.add(simpleGrantedAuthority);

        // return the set of authorities
        return authorities;
    }
}