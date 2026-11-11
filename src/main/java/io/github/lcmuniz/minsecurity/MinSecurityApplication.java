package io.github.lcmuniz.minsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class MinSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(MinSecurityApplication.class, args);
    }
}
