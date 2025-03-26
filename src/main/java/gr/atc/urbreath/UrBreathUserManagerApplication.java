package gr.atc.urbreath;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class UrBreathUserManagerApplication {

	public static void main(String[] args) {
		SpringApplication.run(UrBreathUserManagerApplication.class, args);
	}

}
