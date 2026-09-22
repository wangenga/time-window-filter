package org.example.Classes;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RulebookAnalyzerTest {

    private static final LocalDateTime T = LocalDateTime.of(2024, 3, 15, 2, 0, 0);

    // ---------- helpers ----------

    private LogsReader.LogEntry entry(int lineNumber, String level, String ip, LocalDateTime ts) {
        return new LogsReader.LogEntry(
            lineNumber, "raw " + lineNumber + " " + level + " " + ip, ts, level, ip, "/home", "accessed");
    }

    private LogsReader.LogEntry entry(int lineNumber, String level, String ip) {
        return entry(lineNumber, level, ip, T);
    }

    /** Analyzer loaded with the given rows, e.g. rulebook("INFO,1", "WARN,3"). */
    private RulebookAnalyzer rulebook(String... rows) {
        RulebookAnalyzer a = new RulebookAnalyzer();
        List<String> lines = new java.util.ArrayList<>();
        lines.add("level,severity_score");
        lines.addAll(List.of(rows));
        a.parseRulebook(lines, "test.csv");
        return a;
    }

    private RulebookAnalyzer standard() {
        return rulebook("INFO,1", "WARN,3", "ERROR,5", "ALERT,9");
    }

    private void analyse(RulebookAnalyzer a, List<LogsReader.LogEntry> entries) {
        a.checkLevel(entries);
        a.suspiciousIPs(entries);
    }

    // ---------- rulebook parsing ----------

    @Test
    void parseRulebook_validRows_loadsLevelsInFileOrder() {
        RulebookAnalyzer a = standard();
        assertEquals(List.of("INFO", "WARN", "ERROR", "ALERT"), List.copyOf(a.rulebookContent.keySet()));
        assertEquals(9, a.rulebookContent.get("ALERT"));
    }

    @Test
    void parseRulebook_trimsWhitespaceAroundValues() {
        RulebookAnalyzer a = rulebook(" INFO , 1 ");
        assertEquals(1, a.rulebookContent.get("INFO"));
    }

    @Test
    void parseRulebook_blankLinesAreSkipped() {
        RulebookAnalyzer a = rulebook("INFO,1", "", "WARN,3");
        assertEquals(2, a.rulebookContent.size());
    }

    @Test
    void parseRulebook_emptyInput_throws() {
        RulebookAnalyzer a = new RulebookAnalyzer();
        assertThrows(IllegalArgumentException.class, () -> a.parseRulebook(List.of(), "test.csv"));
    }

    @Test
    void parseRulebook_wrongHeader_throwsAndNamesTheFile() {
        RulebookAnalyzer a = new RulebookAnalyzer();
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> a.parseRulebook(List.of("name,score", "INFO,1"), "rules.csv"));
        assertTrue(e.getMessage().contains("rules.csv"));
    }

    @Test
    void parseRulebook_headerColumnsSwapped_throws() {
        RulebookAnalyzer a = new RulebookAnalyzer();
        assertThrows(IllegalArgumentException.class,
            () -> a.parseRulebook(List.of("severity_score,level", "1,INFO"), "rules.csv"));
    }

    @Test
    void parseRulebook_nonNumericScore_throwsWithLineNumber() {
        RulebookAnalyzer a = new RulebookAnalyzer();
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> a.parseRulebook(List.of("level,severity_score", "INFO,1", "WARN,high"), "rules.csv"));
        assertTrue(e.getMessage().contains("line 3"));
    }

    @Test
    void parseRulebook_rowMissingColumn_throws() {
        RulebookAnalyzer a = new RulebookAnalyzer();
        assertThrows(IllegalArgumentException.class,
            () -> a.parseRulebook(List.of("level,severity_score", "INFO"), "rules.csv"));
    }

    @Test
    void parseRulebook_rowWithExtraColumn_throws() {
        RulebookAnalyzer a = new RulebookAnalyzer();
        assertThrows(IllegalArgumentException.class,
            () -> a.parseRulebook(List.of("level,severity_score", "INFO,1,extra"), "rules.csv"));
    }

    @Test
    void loadRulebook_blankPath_throws() {
        assertThrows(IllegalArgumentException.class, () -> new RulebookAnalyzer().loadRulebook(" "));
    }

    // ---------- matching ----------

    @Test
    void checkLevel_knownLevel_isCountedNotUnknown() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of(entry(1, "INFO", "10.0.0.1")));
        assertEquals(1, a.getStats().get("INFO"));
        assertTrue(a.getUnknownLogs().isEmpty());
    }

    @Test
    void checkLevel_levelNotInRulebook_isUnknownPattern() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of(entry(89, "CRIT", "10.0.0.1")));
        assertEquals(1, a.getUnknownLogs().size());
        assertFalse(a.getStats().containsKey("CRIT"));
    }

    @Test
    void checkLevel_lowerCaseLevel_isUnknownNotMatched() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of(entry(1, "info", "10.0.0.1")));
        assertEquals(0, a.getStats().get("INFO"));
        assertEquals(1, a.getUnknownLogs().size());
    }

    @Test
    void getUnknownLogs_keepsOriginalLineNumbersAndRawContent() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of(entry(89, "CRIT", "10.0.0.1"), entry(154, "DEBUG", "10.0.0.2")));
        List<String> unknown = a.getUnknownLogs();
        assertTrue(unknown.get(0).startsWith("Line 89:"));
        assertTrue(unknown.get(0).contains("raw 89 CRIT 10.0.0.1"));
        assertTrue(unknown.get(1).startsWith("Line 154:"));
    }

    // ---------- counting ----------

    @Test
    void getStats_countsEachKnownLevel() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of(
            entry(1, "INFO", "10.0.0.1"), entry(2, "INFO", "10.0.0.1"), entry(3, "INFO", "10.0.0.2"),
            entry(4, "WARN", "10.0.0.1"), entry(5, "ALERT", "10.0.0.1")));
        Map<String, Integer> stats = a.getStats();
        assertEquals(3, stats.get("INFO"));
        assertEquals(1, stats.get("WARN"));
        assertEquals(0, stats.get("ERROR"));
        assertEquals(1, stats.get("ALERT"));
    }

    @Test
    void getStats_levelWithNoEntries_stillListedAsZero() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of());
        assertEquals(4, a.getStats().size());
        assertTrue(a.getStats().values().stream().allMatch(v -> v == 0));
    }

    @Test
    void getStats_excludesUnknownLevels() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of(entry(1, "CRIT", "10.0.0.1"), entry(2, "info", "10.0.0.1")));
        assertEquals(4, a.getStats().size());
        assertEquals(0, a.getStats().values().stream().mapToInt(Integer::intValue).sum());
    }

    @Test
    void getStats_followsRulebookOrder() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of(entry(1, "ALERT", "10.0.0.1")));
        assertEquals(List.of("INFO", "WARN", "ERROR", "ALERT"), List.copyOf(a.getStats().keySet()));
    }

    // ---------- flagging ----------

    @Test
    void flagging_scoreBelowThree_isNotFlagged() {
        RulebookAnalyzer a = rulebook("LOW,2");
        a.checkLevel(List.of(entry(1, "LOW", "10.0.0.1")));
        assertTrue(a.getFlaggedEntries().isEmpty());
    }

    @Test
    void flagging_scoreExactlyThree_isFlagged() {
        RulebookAnalyzer a = rulebook("MID,3");
        a.checkLevel(List.of(entry(1, "MID", "10.0.0.1")));
        assertEquals(1, a.getFlaggedEntries().size());
    }

    @Test
    void flagging_unknownLevel_isNeverFlagged() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of(entry(1, "CRIT", "10.0.0.1")));
        assertTrue(a.getFlaggedEntries().isEmpty());
    }

    @Test
    void getFlaggedEntries_sortedBySeverityHighestFirst() {
        RulebookAnalyzer a = standard();
        a.checkLevel(List.of(
            entry(1, "WARN", "10.0.0.1"), entry(2, "ALERT", "10.0.0.1"), entry(3, "ERROR", "10.0.0.1")));
        List<String> flagged = a.getFlaggedEntries();
        assertTrue(flagged.get(0).contains("ALERT"));
        assertTrue(flagged.get(1).contains("ERROR"));
        assertTrue(flagged.get(2).contains("WARN"));
    }

    @Test
    void getFlaggedEntries_returnsOriginalRawLineUnchanged() {
        RulebookAnalyzer a = standard();
        LogsReader.LogEntry e = new LogsReader.LogEntry(
            4, "2024-03-15 02:16:02 | ALERT | 203.0.113.42  | /etc/passwd   | read",
            T, "ALERT", "203.0.113.42", "/etc/passwd", "read");
        a.checkLevel(List.of(e));
        assertEquals("2024-03-15 02:16:02 | ALERT | 203.0.113.42  | /etc/passwd   | read",
            a.getFlaggedEntries().get(0));
    }

    // ---------- grouping by IP ----------

    @Test
    void suspiciousIp_countsAllEntriesForThatIp_notOnlyFlaggedOnes() {
        RulebookAnalyzer a = standard();
        analyse(a, List.of(
            entry(1, "INFO", "203.0.113.42"), entry(2, "INFO", "203.0.113.42"),
            entry(3, "WARN", "203.0.113.42"), entry(4, "ALERT", "203.0.113.42")));
        assertEquals(4, a.getSuspiciousIp().get("203.0.113.42"));
    }

    @Test
    void suspiciousIp_includesUnknownPatternEntriesInTotal() {
        RulebookAnalyzer a = standard();
        analyse(a, List.of(entry(1, "WARN", "10.0.0.1"), entry(2, "CRIT", "10.0.0.1")));
        assertEquals(2, a.getSuspiciousIp().get("10.0.0.1"));
    }

    @Test
    void suspiciousIp_ipWithOnlyLowSeverity_isNotListed() {
        RulebookAnalyzer a = standard();
        analyse(a, List.of(entry(1, "INFO", "192.168.1.45"), entry(2, "WARN", "10.0.0.1")));
        assertFalse(a.getSuspiciousIp().containsKey("192.168.1.45"));
        assertTrue(a.getSuspiciousIp().containsKey("10.0.0.1"));
    }

    @Test
    void suspiciousIp_ipWhoseOnlyEntryIsUnknown_isNotListed() {
        RulebookAnalyzer a = standard();
        analyse(a, List.of(entry(1, "CRIT", "10.0.0.9")));
        assertTrue(a.getSuspiciousIp().isEmpty());
    }

    @Test
    void suspiciousIp_sortedByCountHighestFirst() {
        RulebookAnalyzer a = standard();
        analyse(a, List.of(
            entry(1, "WARN", "10.0.0.1"),
            entry(2, "WARN", "10.0.0.2"), entry(3, "INFO", "10.0.0.2"), entry(4, "INFO", "10.0.0.2"),
            entry(5, "WARN", "10.0.0.3"), entry(6, "INFO", "10.0.0.3")));
        assertEquals(List.of("10.0.0.2", "10.0.0.3", "10.0.0.1"), List.copyOf(a.getSuspiciousIp().keySet()));
    }

    @Test
    void suspiciousIp_noEntries_returnsEmptyMap() {
        RulebookAnalyzer a = standard();
        analyse(a, List.of());
        assertTrue(a.getSuspiciousIp().isEmpty());
    }

    // ---------- with the time window ----------

    private static final TimeWindow WINDOW = new TimeWindow(T, T.plusHours(1));

    @Test
    void window_ipTotalCountsOnlyEntriesInsideTheWindow() {
        RulebookAnalyzer a = standard();
        List<LogsReader.LogEntry> all = List.of(
            entry(1, "INFO", "10.0.0.1", T.minusMinutes(5)),    // outside
            entry(2, "WARN", "10.0.0.1", T.plusMinutes(10)),    // inside
            entry(3, "INFO", "10.0.0.1", T.plusMinutes(20)),    // inside
            entry(4, "INFO", "10.0.0.1", T.plusHours(2)));      // outside
        analyse(a, TimeWindow.filter(all, WINDOW));
        assertEquals(2, a.getSuspiciousIp().get("10.0.0.1"));
    }

    @Test
    void window_ipWhoseOnlyFlaggedEntryIsOutside_isNotSuspicious() {
        RulebookAnalyzer a = standard();
        List<LogsReader.LogEntry> all = List.of(
            entry(1, "ALERT", "10.0.0.1", T.minusHours(1)),     // flagged, but outside
            entry(2, "INFO", "10.0.0.1", T.plusMinutes(10)));   // inside, not flagged
        analyse(a, TimeWindow.filter(all, WINDOW));
        assertTrue(a.getSuspiciousIp().isEmpty());
        assertTrue(a.getFlaggedEntries().isEmpty());
    }

    @Test
    void window_unknownPatternKeepsOriginalLineNumber() {
        RulebookAnalyzer a = standard();
        List<LogsReader.LogEntry> all = List.of(
            entry(1, "INFO", "10.0.0.1", T.minusHours(1)),
            entry(89, "CRIT", "10.0.0.1", T.plusMinutes(5)));
        analyse(a, TimeWindow.filter(all, WINDOW));
        assertTrue(a.getUnknownLogs().get(0).startsWith("Line 89:"));
    }

    @Test
    void window_unknownPatternOutsideWindow_isNotReported() {
        RulebookAnalyzer a = standard();
        List<LogsReader.LogEntry> all = List.of(entry(5, "CRIT", "10.0.0.1", T.minusHours(1)));
        analyse(a, TimeWindow.filter(all, WINDOW));
        assertTrue(a.getUnknownLogs().isEmpty());
    }

    @Test
    void window_emptyWindow_givesEmptyFindingsButAllLevelsInSummary() {
        RulebookAnalyzer a = standard();
        List<LogsReader.LogEntry> all = List.of(entry(1, "ALERT", "10.0.0.1", T));
        analyse(a, TimeWindow.filter(all, new TimeWindow(T, T)));
        assertEquals(4, a.getStats().size());
        assertTrue(a.getFlaggedEntries().isEmpty());
        assertTrue(a.getSuspiciousIp().isEmpty());
        assertTrue(a.getUnknownLogs().isEmpty());
    }

    @Test
    void parseRulebook_headerWithSpaces_isAccepted() {
        RulebookAnalyzer a = new RulebookAnalyzer();
        assertDoesNotThrow(() -> a.parseRulebook(List.of(" level , severity_score ", "INFO,1"), "r.csv"));
    }

    @Test
    void parseRulebook_extraHeaderColumn_throws() {
        RulebookAnalyzer a = new RulebookAnalyzer();
        assertThrows(IllegalArgumentException.class,
            () -> a.parseRulebook(List.of("level,severity_score,extra", "INFO,1,foo"), "r.csv"));
    }

    @Test
    void loadRulebook_missingFile_throwsNotFound() {
        RulebookAnalyzer a = new RulebookAnalyzer();
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> a.loadRulebook("definitely-missing-rulebook.csv"));
        assertTrue(e.getMessage().contains("not found"));
    }
}