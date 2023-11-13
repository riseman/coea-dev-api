package com.example.config;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.config.server.EnableConfigServer;

import static org.springframework.boot.SpringApplication.run;


@EnableConfigServer
@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		run(Application.class, args);
	}
}
