package org.example.Classes;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;

class TimeWindowTest {

    private static final LocalDateTime START = LocalDateTime.of(2024, 3, 15, 2, 0, 0);
    private static final LocalDateTime END   = LocalDateTime.of(2024, 3, 15, 3, 30, 0);

    // field order: lineNumber, rawLine, timestamp, level, ip, target, action
    private LogsReader.LogEntry entryAt(int lineNumber, LocalDateTime ts) {
        return new LogsReader.LogEntry(
            lineNumber, "raw line " + lineNumber, ts, "INFO", "10.0.0.1", "/home", "accessed");
    }

    private List<Integer> lineNumbers(List<LogsReader.LogEntry> entries) {
        return entries.stream().map(LogsReader.LogEntry::lineNumber).toList();
    }

    // ---------- contains: boundaries ----------

    @Test
    void contains_entryExactlyAtStart_isInside() {
        assertTrue(new TimeWindow(START, END).contains(START));
    }

    @Test
    void contains_entryExactlyAtEnd_isOutside() {
        assertFalse(new TimeWindow(START, END).contains(END));
    }

    @Test
    void contains_oneSecondBeforeStart_isOutside() {
        assertFalse(new TimeWindow(START, END).contains(START.minusSeconds(1)));
    }

    @Test
    void contains_oneSecondBeforeEnd_isInside() {
        assertTrue(new TimeWindow(START, END).contains(END.minusSeconds(1)));
    }

    @Test
    void contains_entryWellInside_isInside() {
        assertTrue(new TimeWindow(START, END).contains(LocalDateTime.of(2024, 3, 15, 2, 45, 0)));
    }

    @Test
    void contains_entryAfterEnd_isOutside() {
        assertFalse(new TimeWindow(START, END).contains(END.plusHours(5)));
    }

    // ---------- constructor validation ----------

    @Test
    void constructor_startAfterEnd_throwsWithMessageSayingSo() {
        IllegalArgumentException e = assertThrows(
            IllegalArgumentException.class, () -> new TimeWindow(END, START));
        assertTrue(e.getMessage().contains("later"));
    }

    @Test
    void constructor_startOneSecondAfterEnd_throws() {
        assertThrows(IllegalArgumentException.class,
            () -> new TimeWindow(END.plusSeconds(1), END));
    }

    @Test
    void constructor_startEqualsEnd_isValid() {
        assertDoesNotThrow(() -> new TimeWindow(START, START));
    }

    @Test
    void contains_startEqualsEnd_holdsNothing_evenTheBoundaryInstant() {
        TimeWindow empty = new TimeWindow(START, START);
        assertFalse(empty.contains(START));
        assertFalse(empty.contains(START.minusSeconds(1)));
        assertFalse(empty.contains(START.plusSeconds(1)));
    }

    // ---------- filter ----------

    @Test
    void filter_nullWindow_returnsEveryEntry() {
        List<LogsReader.LogEntry> entries = List.of(
            entryAt(1, START.minusDays(10)),
            entryAt(2, END.plusDays(10)));
        assertEquals(List.of(1, 2), lineNumbers(TimeWindow.filter(entries, null)));
    }

    @Test
    void filter_keepsStartEdge_dropsEndEdge() {
        List<LogsReader.LogEntry> entries = List.of(
            entryAt(1, START.minusSeconds(1)),
            entryAt(2, START),
            entryAt(3, END.minusSeconds(1)),
            entryAt(4, END));
        assertEquals(List.of(2, 3), lineNumbers(TimeWindow.filter(entries, new TimeWindow(START, END))));
    }

    @Test
    void filter_windowWithNothingInside_returnsEmptyList() {
        List<LogsReader.LogEntry> entries = List.of(
            entryAt(1, LocalDateTime.of(2024, 3, 15, 1, 0, 0)),
            entryAt(2, LocalDateTime.of(2024, 3, 15, 4, 0, 0)));
        assertTrue(TimeWindow.filter(entries, new TimeWindow(START, END)).isEmpty());
    }

    @Test
    void filter_startEqualsEnd_returnsEmptyEvenWithEntryOnThatInstant() {
        List<LogsReader.LogEntry> entries = List.of(entryAt(1, START));
        assertTrue(TimeWindow.filter(entries, new TimeWindow(START, START)).isEmpty());
    }

    @Test
    void filter_windowEntirelyBeforeLog_returnsEmptyList() {
        List<LogsReader.LogEntry> entries = List.of(entryAt(1, START), entryAt(2, END));
        TimeWindow before = new TimeWindow(START.minusDays(2), START.minusDays(1));
        assertTrue(TimeWindow.filter(entries, before).isEmpty());
    }

    @Test
    void filter_windowEntirelyAfterLog_returnsEmptyList() {
        List<LogsReader.LogEntry> entries = List.of(entryAt(1, START), entryAt(2, END));
        TimeWindow after = new TimeWindow(END.plusDays(1), END.plusDays(2));
        assertTrue(TimeWindow.filter(entries, after).isEmpty());
    }

    @Test
    void filter_windowCoveringEverything_returnsSameEntriesAsNoWindow() {
        List<LogsReader.LogEntry> entries = List.of(entryAt(1, START), entryAt(2, END));
        TimeWindow wide = new TimeWindow(START.minusDays(1), END.plusDays(1));
        assertEquals(TimeWindow.filter(entries, null), TimeWindow.filter(entries, wide));
    }

    @Test
    void filter_keepsOriginalLineNumbers_afterEarlierEntriesAreDropped() {
        List<LogsReader.LogEntry> entries = List.of(
            entryAt(5, START.minusHours(1)),
            entryAt(89, START.plusMinutes(10)),
            entryAt(154, START.plusMinutes(20)));
        assertEquals(List.of(89, 154), lineNumbers(TimeWindow.filter(entries, new TimeWindow(START, END))));
    }

    @Test
    void filter_outOfOrderLog_stillFindsLateEntryAfterOutsideOne() {
        List<LogsReader.LogEntry> entries = List.of(
            entryAt(1, START.plusMinutes(5)),
            entryAt(2, END.plusHours(1)),          // out of window, appears mid-file
            entryAt(3, START.plusMinutes(10)));    // in window, appears after it
        assertEquals(List.of(1, 3), lineNumbers(TimeWindow.filter(entries, new TimeWindow(START, END))));
    }

    @Test
    void filter_preservesOriginalOrder() {
        List<LogsReader.LogEntry> entries = List.of(
            entryAt(1, START.plusMinutes(30)),
            entryAt(2, START.plusMinutes(10)),
            entryAt(3, START.plusMinutes(20)));
        assertEquals(List.of(1, 2, 3), lineNumbers(TimeWindow.filter(entries, new TimeWindow(START, END))));
    }

    @Test
    void filter_keepsRawLineUnchanged() {
        LogsReader.LogEntry e = entryAt(7, START.plusMinutes(1));
        assertEquals("raw line 7", TimeWindow.filter(List.of(e), new TimeWindow(START, END)).get(0).rawline());
    }

    @Test
    void filter_emptyInput_returnsEmptyList() {
        assertTrue(TimeWindow.filter(List.of(), new TimeWindow(START, END)).isEmpty());
    }

    // ---------- describe (header line) ----------

    @Test
    void describe_nullWindow_saysFullFile() {
        assertEquals("Time Window: full file", TimeWindow.describe(null));
    }

    @Test
    void describe_window_usesLogTimestampFormat() {
        assertEquals("Time Window: 2024-03-15 02:00:00 to 2024-03-15 03:30:00",
            TimeWindow.describe(new TimeWindow(START, END)));
    }
}