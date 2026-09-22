package org.example.Classes;

import java.time.LocalDateTime;
import java.util.List;

public record TimeWindow(LocalDateTime start, LocalDateTime end) {


    public TimeWindow {
        if (start.isAfter(end))
            throw new IllegalArgumentException(
                "Start time " + LogsReader.FORMAT.format(start) + " is later than end time " + LogsReader.FORMAT.format(end));
    }

    public boolean contains(LocalDateTime t) {
        return !t.isBefore(start) && t.isBefore(end);
    }

    public static List<LogsReader.LogEntry> filter(List<LogsReader.LogEntry> entries, TimeWindow window) {
        if (window == null) return entries;
        return entries.stream().filter(e -> window.contains(e.timestamp())).toList();
    }

    public static String describe(TimeWindow window) {
        return window == null
            ? "Time Window: full file"
            : "Time Window: " + LogsReader.FORMAT.format(window.start()) + " to " + LogsReader.FORMAT.format(window.end());
    }
}