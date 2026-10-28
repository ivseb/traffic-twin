package rt;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Red team round 3: Spring Boot app, traffic-twin attached only with -javaagent (zero-code).
 * The app never logs request data itself.
 */
@SpringBootApplication
@RestController
public class App {
  public static void main(String[] args) {
    SpringApplication.run(App.class, args);
  }

  @GetMapping(value = "/health", produces = MediaType.TEXT_PLAIN_VALUE)
  public String health() {
    return "ok";
  }

  @SuppressWarnings("unchecked")
  @PostMapping("/orders/{id}")
  public ResponseEntity<Map<String, Object>> order(@PathVariable String id, @RequestBody Map<String, Object> b,
      @RequestHeader(value = "x-secret", required = false) String secret) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("id", id);
    out.put("status", "created");
    out.put("echo", b.get("secret"));
    Object nested = b.get("nested");
    out.put("email", nested instanceof Map ? ((Map<String, Object>) nested).get("email") : null);
    return ResponseEntity.status(201)
        .header("x-echo", secret == null ? "" : secret)
        .header(HttpHeaders.SET_COOKIE, "sess=" + b.get("secret") + "; Path=/")
        .body(out);
  }

  /** Unhandled: Spring answers 500 and logs the exception (the app's own log). */
  @GetMapping("/boom/{v}")
  public String boom(@PathVariable String v) {
    throw new IllegalStateException("boom " + v);
  }

  @GetMapping("/fail/{v}")
  public ResponseEntity<Map<String, Object>> fail(@PathVariable String v) {
    return ResponseEntity.status(500)
        .body(Map.of("error", Map.of("code", "E_FAIL", "message", "order " + v + " failed")));
  }
}
