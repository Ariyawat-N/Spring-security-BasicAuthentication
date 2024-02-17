package com.example.securitycourse.service;

import com.example.securitycourse.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationUserDetailService implements UserDetailsService {
    private  final UserRepository userRepository;

    public AuthenticationUserDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findUserByUsername(username);
    }
}

/*
@Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        CustomUserDetail user = new CustomUserDetail("member",encoder.encode("password"));
        user.setRoles(List.of("MEMBER"));
        user.setPermissions(List.of("MEMBER_READ"));


//        UserDetails user = User.withUsername("member")
//                .password(encoder.encode("password"))
//                .roles("MEMBER") // ROLE_MEMBER
//                .authorities("MEMBER_READ")
//                .build();

        UserDetails admin = User.withUsername("admin")
                .password(encoder.encode("password"))
                .roles("ADMIN") // ROLE_ADMIN
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
*/