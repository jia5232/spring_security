package com.hello.springsecurityjwt.controller;

import com.hello.springsecurityjwt.dto.JoinDTO;
import com.hello.springsecurityjwt.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {
    private final JoinService joinService;
    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO){ //@ModelAttribute 생략?
        joinService.joinProcess(joinDTO);
        return "ok";
    }
}
