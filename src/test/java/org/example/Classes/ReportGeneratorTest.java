package org.example.Classes;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ReportGeneratorTest {

    private static final LocalDateTime GENERATED = LocalDateTime.of(2024, 3, 15, 9, 0, 0);
    private static final TimeWindow WINDOW = new TimeWindow(
        LocalDateTime.of(2024, 3, 15, 2, 0, 0), LocalDateTime.of(2024, 3, 15, 3, 30, 0));

    // ---------- helpers ----------

    private String report(TimeWindow window,
                          Map<String, Integer> summary,
                          List<String> flagged,
                          Map<String, Integer> susIp,
                          List<String> unknown,
                          List<LogsReader.LineIssue> malformed) {
        return ReportGenerator.buildReport(GENERATED, window, summary, flagged, susIp, unknown, malformed);
    }

    private String emptyReport(TimeWindow window) {
        return report(window, Map.of(), List.of(), Map.of(), List.of(), List.of());
    }

    /** Text between a section header and the next section header, trimmed. */
    private String section(String report, String header) {
        int start = report.indexOf(header);
        assertTrue(start >= 0, "missing section: " + header);
        start += header.length();
        int next = report.indexOf("\n--- ", start);
        return report.substring(start, next == -1 ? report.length() : next).trim();
    }

    // ---------- header ----------

    @Test
    void header_startsWithTitleThenGeneratedTimeThenWindowLine() {
        String[] lines = emptyReport(WINDOW).split("\n");
        assertEquals("=== Log Analysis Report ===", lines[0]);
        assertEquals("Generated: 2024-03-15 09:00:00", lines[1]);
        assertEquals("Time Window: 2024-03-15 02:00:00 to 2024-03-15 03:30:00", lines[2]);
    }

    @Test
    void header_noWindow_saysFullFileDirectlyUnderGenerated() {
        String[] lines = emptyReport(null).split("\n");
        assertEquals("Generated: 2024-03-15 09:00:00", lines[1]);
        assertEquals("Time Window: full file", lines[2]);
    }

    // ---------- structure ----------

    @Test
    void sections_allFiveAppearInTheRequiredOrder() {
        String r = emptyReport(null);
        int a = r.indexOf("--- Activity Summary ---");
        int b = r.indexOf("--- Flagged Entries ---");
        int c = r.indexOf("--- Suspicious Activity by IP ---");
        int d = r.indexOf("--- Unknown Patterns ---");
        int e = r.indexOf("--- Malformed Lines ---");
        assertTrue(a >= 0 && a < b && b < c && c < d && d < e);
    }

    @Test
    void sections_emptyOnes_eachShowSingleNoneFoundLine() {
        String r = emptyReport(null);
        assertEquals("None found", section(r, "--- Activity Summary ---"));
        assertEquals("None found", section(r, "--- Flagged Entries ---"));
        assertEquals("None found", section(r, "--- Suspicious Activity by IP ---"));
        assertEquals("None found", section(r, "--- Unknown Patterns ---"));
        assertEquals("None found", section(r, "--- Malformed Lines ---"));
    }

    @Test
    void sections_withContent_doNotShowNoneFound() {
        String r = report(null,
            Map.of("INFO", 1), List.of("flagged line"), Map.of("10.0.0.1", 1),
            List.of("Line 4: unknown"), List.of(new LogsReader.LineIssue(2, "bad")));
        assertFalse(r.contains("None found"));
    }

    // ---------- activity summary ----------

    @Test
    void activitySummary_listsLevelsAndCountsInGivenOrder() {
        Map<String, Integer> summary = new LinkedHashMap<>();
        summary.put("INFO", 42);
        summary.put("WARN", 15);
        summary.put("ALERT", 0);
        String r = report(null, summary, List.of(), Map.of(), List.of(), List.of());
        assertEquals("INFO: 42\nWARN: 15\nALERT: 0", section(r, "--- Activity Summary ---"));
    }

    // ---------- flagged entries ----------

    @Test
    void flaggedEntries_rawLinesAppearUnchangedIncludingSpacing() {
        String raw = "2024-03-15 02:16:02 | ALERT | 203.0.113.42  | /etc/passwd   | read";
        String r = report(null, Map.of(), List.of(raw), Map.of(), List.of(), List.of());
        assertEquals(raw, section(r, "--- Flagged Entries ---"));
    }

    @Test
    void flaggedEntries_keepTheOrderTheyWereGiven() {
        String r = report(null, Map.of(), List.of("first", "second", "third"),
            Map.of(), List.of(), List.of());
        assertEquals("first\nsecond\nthird", section(r, "--- Flagged Entries ---"));
    }

    // ---------- suspicious IPs ----------

    @Test
    void suspiciousIps_appearInReport() {
        Map<String, Integer> susIp = new LinkedHashMap<>();
        susIp.put("203.0.113.42", 8);
        susIp.put("198.51.100.7", 2);
        String r = report(null, Map.of(), List.of(), susIp, List.of(), List.of());
        assertTrue(r.contains("203.0.113.42: 8 entries"));
        assertTrue(r.contains("198.51.100.7: 2 entries"));
    }

    @Test
    void suspiciousIps_keepTheGivenHighestFirstOrder() {
        Map<String, Integer> susIp = new LinkedHashMap<>();
        susIp.put("203.0.113.42", 8);
        susIp.put("198.51.100.7", 2);
        String r = report(null, Map.of(), List.of(), susIp, List.of(), List.of());
        assertEquals("203.0.113.42: 8 entries\n198.51.100.7: 2 entries",
            section(r, "--- Suspicious Activity by IP ---"));
    }

    // ---------- unknown patterns ----------

    @Test
    void unknownPatterns_appearWithTheirLineNumbers() {
        String r = report(null, Map.of(), List.of(), Map.of(),
            List.of("Line 89: 2024-03-15 03:42:11 | CRIT  | 203.0.113.42 | /admin | escalated",
                    "Line 154: 2024-03-15 04:01:33 | DEBUG | 192.168.1.20 | /test  | ???"),
            List.of());
        String s = section(r, "--- Unknown Patterns ---");
        assertTrue(s.startsWith("Line 89:"));
        assertTrue(s.contains("\nLine 154:"));
    }

    // ---------- malformed lines ----------

    @Test
    void malformedLines_appearInReport() {
        List<LogsReader.LineIssue> malformed = List.of(
            new LogsReader.LineIssue(23, "2024-03-15 02:17:00 | WARN | 203.0.113.42 | /login"));
        String r = report(null, Map.of(), List.of(), Map.of(), List.of(), malformed);
        assertTrue(r.contains("Line 23: 2024-03-15 02:17:00 | WARN | 203.0.113.42 | /login"));
    }

    @Test
    void malformedLines_stillListedWhenAWindowIsSet() {
        List<LogsReader.LineIssue> malformed = List.of(new LogsReader.LineIssue(51, "not-a-timestamp | INFO"));
        String r = report(WINDOW, Map.of(), List.of(), Map.of(), List.of(), malformed);
        assertEquals("Line 51: not-a-timestamp | INFO", section(r, "--- Malformed Lines ---"));
    }

    @Test
    void malformedLines_emptyRawContentStillListedWithLineNumber() {
        String r = report(null, Map.of(), List.of(), Map.of(), List.of(),
            List.of(new LogsReader.LineIssue(7, "")));
        assertTrue(r.contains("Line 7:"));
    }

    // ---------- empty window ----------

    @Test
    void emptyWindow_reportIsStillCompleteWithZeroedSummary() {
        Map<String, Integer> zeros = new LinkedHashMap<>();
        zeros.put("INFO", 0);
        zeros.put("ALERT", 0);
        String r = report(new TimeWindow(WINDOW.start(), WINDOW.start()),
            zeros, List.of(), Map.of(), List.of(), List.of());
        assertTrue(r.contains("Time Window: 2024-03-15 02:00:00 to 2024-03-15 02:00:00"));
        assertEquals("INFO: 0\nALERT: 0", section(r, "--- Activity Summary ---"));
        assertEquals("None found", section(r, "--- Flagged Entries ---"));
        assertEquals("None found", section(r, "--- Malformed Lines ---"));
    }
}