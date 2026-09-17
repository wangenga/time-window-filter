package org.example.Classes;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class RulebookAnalyzerTest {

    @TempDir
    Path tempDir;

    private RulebookAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new RulebookAnalyzer();
    }

    /** Writes a rulebook CSV and points the analyzer at it. */
    private void loadRulebook(String csvContent) throws IOException {
        Path csv = tempDir.resolve("rules.csv");
        Files.writeString(csv, csvContent);
        analyzer.getRulebookPath(csv.toString());
    }

    /** Builds a well-formed log line: field0|severity|ip|field3|field4 */
    private String log(String severity, String ip) {
        return "2024-01-01 10:00:00|" + severity + "|" + ip + "|action|user";
    }

    /** Runs checkLevel with an auto-generated "numbered" list of the same size. */
    private void process(List<String> logs) {
        List<String> numbered = new ArrayList<>();
        for (int i = 1; i <= logs.size(); i++) numbered.add("line-" + i);
        analyzer.checkLevel(logs, numbered);
    }

    /** Builds a LogEntry matching the same shape as log(severity, ip). */
    private LogsReader.LogEntry entry(int lineNumber, String severity, String ip) {
        return new LogsReader.LogEntry(lineNumber, "2024-01-01 10:00:00", severity, ip, "action", "user");
    }

    @Test
    void getRulebookPath_loadsValidCsv() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\nERROR,5\nINFO,1\n");

        // The map was populated — verified indirectly through checkLevel
        process(List.of(log("WARN", "1.1.1.1")));
        assertEquals(1, analyzer.getFlaggedEntries().size());
        assertEquals(1, analyzer.getStats().get("WARN"));
    }

    @Test
    void getRulebookPath_throwsWhenHeadersAreWrong() throws IOException {
        Path csv = tempDir.resolve("bad.csv");
        Files.writeString(csv, "level,score\nWARN,3\n");

        assertThrows(IllegalArgumentException.class,
                () -> analyzer.getRulebookPath(csv.toString()));
    }

    @Test
    void getRulebookPath_acceptsHeadersWithSpaces() throws IOException {
        Path csv = tempDir.resolve("spaced.csv");
        Files.writeString(csv, " level , severity_score \nWARN,3\n");

        assertDoesNotThrow(() -> analyzer.getRulebookPath(csv.toString()));
    }

    @Test
    void getRulebookPath_handlesEmptyFile() throws IOException {
        Path csv = tempDir.resolve("empty.csv");
        Files.createFile(csv);

        // Should not throw — just prints "Rulebook is empty."
        assertDoesNotThrow(() -> analyzer.getRulebookPath(csv.toString()));

        process(List.of(log("WARN", "1.1.1.1")));
        // No rulebook entries → everything unknown
        assertEquals(1, analyzer.getUnknownLogs().size());
        assertTrue(analyzer.getFlaggedEntries().isEmpty());
    }

    @Test
    void checkLevel_countsAnyKnownSeverityNotJustHardcodedOnes() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\nDEBUG,1\nCRITICAL,5\nNOTICE,2\n");

        process(List.of(
                log("WARN",     "1.1.1.1"),
                log("DEBUG",    "2.2.2.2"),
                log("WARN",     "3.3.3.3"),
                log("CRITICAL", "4.4.4.4"),
                log("NOTICE",   "5.5.5.5")
        ));

        Map<String, Integer> stats = analyzer.getStats();
        assertEquals(2, stats.get("WARN"));
        assertEquals(1, stats.get("DEBUG"));
        assertEquals(1, stats.get("CRITICAL"));
        assertEquals(1, stats.get("NOTICE"));
    }

    @Test
    void checkLevel_flagsOnlyScoresGreaterOrEqualThree() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\nDEBUG,1\nCRITICAL,5\nNOTICE,2\n");

        process(List.of(
                log("WARN",     "1.1.1.1"),   // flagged (3)
                log("DEBUG",    "2.2.2.2"),   // not flagged (1)
                log("CRITICAL", "3.3.3.3"),   // flagged (5)
                log("NOTICE",   "4.4.4.4")    // not flagged (2)
        ));

        List<String> flagged = analyzer.getFlaggedEntries();
        assertEquals(2, flagged.size());
        assertTrue(flagged.contains(log("WARN", "1.1.1.1")));
        assertTrue(flagged.contains(log("CRITICAL", "3.3.3.3")));
        assertFalse(flagged.contains(log("DEBUG", "2.2.2.2")));
        assertFalse(flagged.contains(log("NOTICE", "4.4.4.4")));
    }

    @Test
    void checkLevel_unknownSeverityGoesToUnknownLogsUsingNumberedVersion() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\n");

        List<String> valid = List.of(log("BANANA", "1.1.1.1"));
        List<String> numbered = List.of("Line #7: BANANA entry");

        analyzer.checkLevel(valid, numbered);

        assertTrue(analyzer.getFlaggedEntries().isEmpty());
        assertEquals(1, analyzer.getUnknownLogs().size());
        assertEquals("Line #7: BANANA entry", analyzer.getUnknownLogs().get(0));
        assertFalse(analyzer.getStats().containsKey("BANANA"));
    }

    @Test
    void checkLevel_severityIsTrimmedBeforeLookup() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\n");

        process(List.of("t|  WARN  |1.1.1.1|x|y"));

        assertEquals(1, analyzer.getFlaggedEntries().size());
        assertEquals(1, analyzer.getStats().get("WARN"));
    }



    @Test
    void checkLevel_emptyInputProducesNothing() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\n");

        analyzer.checkLevel(Collections.emptyList(), Collections.emptyList());

        assertTrue(analyzer.getFlaggedEntries().isEmpty());
        assertTrue(analyzer.getUnknownLogs().isEmpty());
        assertTrue(analyzer.getStats().isEmpty());
    }

    @Test
    void checkLevel_preservesInsertionOrderOfFlaggedLogs() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\nERROR,4\nALERT,5\n");

        String l1 = log("WARN",  "1.1.1.1");
        String l2 = log("ERROR", "2.2.2.2");
        String l3 = log("ALERT", "3.3.3.3");
        process(List.of(l1, l2, l3));

        List<String> flagged = analyzer.getFlaggedEntries();
        assertEquals(l3, flagged.get(0)); // ALERT, score 5 — highest, comes first
        assertEquals(l2, flagged.get(1)); // ERROR, score 4 — middle
        assertEquals(l1, flagged.get(2)); // WARN, score 3 — lowest, comes last
    }

    @Test
    void getStats_isEmptyBeforeProcessing() {
        assertTrue(analyzer.getStats().isEmpty());
    }

    @Test
    void getStats_returnsDescendingOrderByCount() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\nDEBUG,1\nCRITICAL,5\n");

        process(List.of(
                log("WARN", "1.1.1.1"),
                log("WARN", "2.2.2.2"),
                log("WARN", "3.3.3.3"),
                log("DEBUG", "4.4.4.4"),
                log("DEBUG", "5.5.5.5"),
                log("CRITICAL", "6.6.6.6")
        ));

        List<String> keys = new ArrayList<>(analyzer.getStats().keySet());
        assertEquals("WARN",     keys.get(0));   // count 3
        assertEquals("DEBUG",    keys.get(1));   // count 2
        assertEquals("CRITICAL", keys.get(2));   // count 1
    }

    @Test
    void suspiciousIPs_countsDuplicateIpsAmongFlaggedLogs() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\nERROR,4\n");

        process(List.of(
                log("WARN",  "1.1.1.1"),
                log("WARN",  "1.1.1.1"),
                log("ERROR", "1.1.1.1"),
                log("ERROR", "2.2.2.2")
        ));

        analyzer.suspiciousIPs(List.of(
            entry(1, "WARN",  "1.1.1.1"),
            entry(2, "WARN",  "1.1.1.1"),
            entry(3, "ERROR", "1.1.1.1"),
            entry(4, "ERROR", "2.2.2.2")
        ));

        Map<String, Integer> counts = analyzer.getSuspiciousIp();
        assertEquals(3, counts.get("1.1.1.1"));
        assertEquals(1, counts.get("2.2.2.2"));
    }

    @Test
    void suspiciousIPs_ignoresNonFlaggedLogs() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\nDEBUG,1\n");

        process(List.of(
                log("DEBUG", "9.9.9.9"),  // not flagged
                log("WARN",  "1.1.1.1")   // flagged
        ));

        analyzer.suspiciousIPs(List.of(
            entry(1, "DEBUG", "9.9.9.9"),
            entry(2, "WARN",  "1.1.1.1")
        ));

        Map<String, Integer> counts = analyzer.getSuspiciousIp();
        assertFalse(counts.containsKey("9.9.9.9"));
        assertTrue(counts.containsKey("1.1.1.1"));
    }

    @Test
    void suspiciousIPs_emptyWhenNoFlaggedLogs() throws IOException {
        loadRulebook("level,severity_score\nDEBUG,1\n");

        process(List.of(log("DEBUG", "1.1.1.1")));
        analyzer.suspiciousIPs(List.of(
            entry(1, "DEBUG", "1.1.1.1")
        ));

        assertTrue(analyzer.getSuspiciousIp().isEmpty());
    }

    @Test
    void getSuspiciousIp_returnsDescendingOrderByCount() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\n");

        process(List.of(
                log("WARN", "1.1.1.1"),
                log("WARN", "2.2.2.2"),
                log("WARN", "2.2.2.2"),
                log("WARN", "2.2.2.2"),
                log("WARN", "3.3.3.3"),
                log("WARN", "3.3.3.3")
        ));

        analyzer.suspiciousIPs(List.of(
            entry(1, "WARN", "1.1.1.1"),
            entry(2, "WARN", "2.2.2.2"),
            entry(3, "WARN", "2.2.2.2"),
            entry(4, "WARN", "2.2.2.2"),
            entry(5, "WARN", "3.3.3.3"),
            entry(6, "WARN", "3.3.3.3")
    ));

        List<String> orderedIps = new ArrayList<>(analyzer.getSuspiciousIp().keySet());
        assertEquals(List.of("2.2.2.2", "3.3.3.3", "1.1.1.1"), orderedIps);
    }

    @Test
    void getFlaggedEntries_returnsTheFlaggedLogs() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\n");

        String l = log("WARN", "1.1.1.1");
        process(List.of(l));

        assertEquals(1, analyzer.getFlaggedEntries().size());
        assertEquals(l, analyzer.getFlaggedEntries().get(0));
    }

    @Test
    void getUnknownLogs_returnsTheNumberedVersions() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\n");

        List<String> valid = List.of(log("NOPE", "1.1.1.1"));
        List<String> numbered = List.of("numbered-1");
        analyzer.checkLevel(valid, numbered);

        assertEquals(List.of("numbered-1"), analyzer.getUnknownLogs());
    }

    @Test
    void suspiciousIPs_countsAllEntriesForIpNotJustFlaggedOnes() throws IOException {
        loadRulebook("level,severity_score\nWARN,3\n");

        process(List.of(
                log("WARN", "1.1.1.1"),   // flagged
                log("INFO", "1.1.1.1"),   // not flagged, same IP
                log("INFO", "1.1.1.1")    // not flagged, same IP
        ));

        analyzer.suspiciousIPs(List.of(
                entry(1, "WARN", "1.1.1.1"),
                entry(2, "INFO", "1.1.1.1"),
                entry(3, "INFO", "1.1.1.1")
        ));

        // 1.1.1.1 is suspicious (has ≥1 flagged entry), and should show its TOTAL entry count (3), not just the flagged one (1)
        assertEquals(3, analyzer.getSuspiciousIp().get("1.1.1.1"));
    }
}