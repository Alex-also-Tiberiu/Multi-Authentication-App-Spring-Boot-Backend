package com.panda.security.feature.demo.controller;

import io.swagger.v3.oas.annotations.Hidden;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo-controller")
//@Hidden
public class DemoController {
  private static final Logger log = LoggerFactory.getLogger(DemoController.class);

  @GetMapping
  public ResponseEntity<String> sayHello() {
    log.info("Calling say hello api");
    return ResponseEntity.ok("Hello from secured endpoint");
  }

}
