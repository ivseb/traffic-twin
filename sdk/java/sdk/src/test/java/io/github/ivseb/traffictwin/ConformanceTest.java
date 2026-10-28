package io.github.ivseb.traffictwin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.github.ivseb.traffictwin.sanitizer.VectorRunner;
import io.github.ivseb.traffictwin.sanitizer.VectorRunner.VectorResult;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/** Runs every conformance vector (conformance/vectors/*.json) byte for byte (sanitizer.md 16). */
class ConformanceTest {
    static Path dir() {
        return Path.of(System.getProperty("tt.conformance.dir", "../../../conformance")).toAbsolutePath().normalize();
    }

    @TestFactory
    Stream<DynamicTest> vectors() throws Exception {
        Path root = dir();
        List<Path> files;
        try (Stream<Path> s = Files.list(root.resolve("vectors"))) {
            files = s.filter(p -> p.getFileName().toString().endsWith(".json")).sorted().toList();
        }
        assertFalse(files.isEmpty(), "no vectors under " + root);
        return files.stream().map(f -> DynamicTest.dynamicTest(f.getFileName().toString().replace(".json", ""), () -> {
            Map<String, Object> vec = VectorRunner.parse(Files.readAllBytes(f));
            @SuppressWarnings("unchecked")
            Map<String, Object> exp = (Map<String, Object>) vec.get("expected");
            VectorResult got = VectorRunner.run(vec, root);
            assertEquals(exp.get("outcome"), got.outcome(), "outcome of " + f.getFileName() + ": " + got);
            switch ((String) exp.get("outcome")) {
                case "event" -> assertEquals(
                    new String(((String) exp.get("canonical")).getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8), got.canonical());
                case "not_sampled" -> assertEquals(exp.get("sampled_by"), got.sampledBy());
                default -> assertEquals(exp.get("code"), got.code());
            }
        }));
    }
}
