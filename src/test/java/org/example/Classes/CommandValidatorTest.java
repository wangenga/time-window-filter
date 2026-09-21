package org.example.Classes;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;

class CommandValidatorTest {

    private static final String S = "2024-03-15 02:00:00";
    private static final String E = "2024-03-15 03:30:00";

    private CommandValidator.Config parse(String... args) {
        return CommandValidator.parse(args);
    }

    private String messageFor(String... args) {
        return assertThrows(IllegalArgumentException.class, () -> CommandValidator.parse(args)).getMessage();
    }

    // ---------- argument count ----------

    @Test
    void threeArgs_noWindow_pathsInOrder() {
        CommandValidator.Config c = parse("logs.txt", "rules.csv", "report.txt");
        assertEquals("logs.txt", c.logPath());
        assertEquals("rules.csv", c.rulesPath());
        assertEquals("report.txt", c.reportPath());
        assertNull(c.window());
    }

    @Test
    void fiveArgs_buildsWindowFromArgs4And5() {
        CommandValidator.Config c = parse("l", "r", "o", S, E);
        assertEquals(LocalDateTime.of(2024, 3, 15, 2, 0, 0), c.window().start());
        assertEquals(LocalDateTime.of(2024, 3, 15, 3, 30, 0), c.window().end());
    }

    @Test
    void wrongArgCounts_throwWithCountAndUsage() {
        for (int n : new int[]{0, 1, 2, 4, 6}) {
            String m = messageFor(new String[n]);
            assertTrue(m.contains(String.valueOf(n)), "count " + n);
            assertTrue(m.contains("Usage"), "usage " + n);
        }
    }

    // ---------- names don't matter ----------

    @Test
    void anyFileNamesAreAccepted() {
        CommandValidator.Config c = parse("access.log", "rules.dat", "out.report");
        assertEquals("out.report", c.reportPath());
    }

    // ---------- bad timestamps ----------

    @Test
    void unparseableStart_messageSaysStart() {
        assertTrue(messageFor("l", "r", "o", "nonsense", E).contains("start"));
    }

    @Test
    void unparseableEnd_messageSaysEnd() {
        assertTrue(messageFor("l", "r", "o", S, "nonsense").contains("end"));
    }

    @Test
    void impossibleDate_isRejected() {
        assertThrows(IllegalArgumentException.class, () -> parse("l", "r", "o", "2024-02-30 02:00:00", E));
    }

    @Test
    void wrongFormats_areRejected() {
        assertThrows(IllegalArgumentException.class, () -> parse("l", "r", "o", "2024/03/15 02:00:00", E));
        assertThrows(IllegalArgumentException.class, () -> parse("l", "r", "o", "2024-03-15", E));
        assertThrows(IllegalArgumentException.class, () -> parse("l", "r", "o", S, ""));
    }

    @Test
    void timestampWithSurroundingSpaces_isAccepted() {
        assertNotNull(parse("l", "r", "o", " " + S + " ", E).window());
    }

    @Test
    void logFormatParsesNormalTimestamp_regressionForStrictYear() {
        assertEquals(LocalDateTime.of(2024, 3, 15, 2, 0, 0), LocalDateTime.parse(S, LogsReader.FORMAT));
    }

    // ---------- window ordering ----------

    @Test
    void startAfterEnd_throwsAndSaysSo() {
        assertTrue(messageFor("l", "r", "o", E, S).contains("later"));
    }

    @Test
    void startOneSecondAfterEnd_throws() {
        assertThrows(IllegalArgumentException.class, () -> parse("l", "r", "o", "2024-03-15 02:00:01", S));
    }

    @Test
    void startEqualsEnd_isValid() {
        assertNotNull(parse("l", "r", "o", S, S).window());
    }
}