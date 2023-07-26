package com.pokemonreview.api.controllers;

import com.pokemonreview.api.dto.AuthResponseDto;
import com.pokemonreview.api.dto.LoginDto;
import com.pokemonreview.api.dto.UserDto;
import com.pokemonreview.api.models.Role;
import com.pokemonreview.api.models.UserEntity;
import com.pokemonreview.api.repository.RoleRepository;
import com.pokemonreview.api.repository.UserRepository;

import com.pokemonreview.api.security.JWTGenerator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Optional;

/*
user 등록
http://localhost:8080/api/auth/register
{
    "username":"admin",
    "password":"123456",
    "firstName":"dooly",
    "lastName":"park",
    "role":"ROLE_ADMIN"
}

user token 로그인
http://localhost:8080/api/auth/login
{
    "password":"123456",
    "username":"admin"
}
*/
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTGenerator jwtGenerator;

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome this endpoint is not secure";
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody UserDto userDto) {
        if (userRepository.existsByUsername(userDto.getUsername())) {
            return new ResponseEntity<>("Username is taken!", HttpStatus.BAD_REQUEST);
        }

        UserEntity user = new UserEntity();
        user.setUsername(userDto.getUsername());
        user.setPassword(passwordEncoder.encode((userDto.getPassword())));
        user.setFirstName(userDto.getFirstName());
        user.setLastName(userDto.getLastName());

        Role roles = roleRepository.findByName(userDto.getRole())
                .orElseGet(() -> {
                    System.out.println("Role 없음");
                    Role role = new Role();
                    role.setName(userDto.getRole());
                    return roleRepository.save(role);
                });
        user.setRoles(Collections.singletonList(roles));
        userRepository.save(user);

        return new ResponseEntity<>("User registered success!", HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDto> login(@RequestBody LoginDto loginDto){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginDto.getUsername(),
                        loginDto.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        //token 생성
        String token = jwtGenerator.generateToken(authentication);

        AuthResponseDto authResponseDTO = new AuthResponseDto(token);
        authResponseDTO.setUsername(loginDto.getUsername());

        Optional<UserEntity> optionalUser =
                userRepository.findByUsername(loginDto.getUsername());
        if(optionalUser.isPresent()){
            UserEntity userEntity = optionalUser.get();
            authResponseDTO.setRole(userEntity.getRoles().get(0).getName());
        }
        return new ResponseEntity<>(authResponseDTO, HttpStatus.OK);
    }
}