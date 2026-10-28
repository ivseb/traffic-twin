package io.github.ivseb.traffictwin.servlet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** The "the application read one whole JSON document" test the filter uses for chunked bodies. */
class CompleteJsonTest {
    private static boolean c(String s) {
        return TrafficTwinFilter.completeJson(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void wholeDocuments() {
        assertTrue(c("{}"));
        assertTrue(c(" \r\n{\"a\":[1,{\"b\":\"}\"}],\"c\":\"\\\"}\"}\n"));
        assertTrue(c("[1,2,3]"));
    }

    @Test
    void truncatedOrTrailingOrNotJson() {
        assertFalse(c(""));
        assertFalse(c("{\"a\":1"));
        assertFalse(c("{\"a\":\"}"));
        assertFalse(c("{\"a\":1}{\"b\":2}"));
        assertFalse(c("{\"a\":1} x"));
        assertFalse(c("plain text"));
        assertFalse(c("42"));
    }
}
