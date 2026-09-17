package org.example.Classes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ReportGeneratorTest {

    @Test
    void malformedLinesAppearInReport() {
        // Arrange
        Map<String, Integer> activitySummary = Map.of();
        List<String> flaggedEntries = List.of();
        Map<String, Integer> susIp = Map.of();
        List<String> unknownlogs = List.of();
        List<LogsReader.LineIssue> malformedLines = List.of(
            new LogsReader.LineIssue(23, "2024-03-15 02:17:00 | WARN | 203.0.113.42 | /login")
        );
        
        

        // Act
        String report = ReportGenerator.buildReport(activitySummary, flaggedEntries, susIp, unknownlogs, malformedLines);

        // Assert
        assertTrue(report.contains("Line 23: 2024-03-15 02:17:00 | WARN | 203.0.113.42 | /login"));
    }

    @Test
    void suspiciousIpsAppearInReport() {
        // Arrange
        Map<String, Integer> activitySummary = Map.of();
        List<String> flaggedEntries = List.of();
        Map<String, Integer> susIp = new LinkedHashMap<>();
        susIp.put("203.0.113.42", 8);
        susIp.put("198.51.100.7", 2);
        List<String> unknownLogs = List.of();
        List<LogsReader.LineIssue> malformedLines = List.of();

        // Act
        String report = ReportGenerator.buildReport(activitySummary, flaggedEntries, susIp, unknownLogs, malformedLines);

        // Assert
        assertTrue(report.contains("203.0.113.42: 8 entries"));
        assertTrue(report.contains("198.51.100.7: 2 entries"));
    }
}

