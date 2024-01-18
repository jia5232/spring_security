package com.hello.springsecurityjwt.service;

import com.hello.springsecurityjwt.dto.CustomUserDetails;
import com.hello.springsecurityjwt.entity.UserEntity;
import com.hello.springsecurityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //DB에서 조회
        UserEntity userData = userRepository.findByUsername(username);

        //UserDetails에 담아서 return하면 AutneticationManager가 검증 함
        if(userData != null){
            return new CustomUserDetails(userData);
        }

        return null;
    }
}
