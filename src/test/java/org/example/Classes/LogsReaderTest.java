package org.example.Classes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.List;

import org.junit.jupiter.api.Test;

class LogsReaderTest {
    
    @Test
    void cleanLineBecomesLogEntry() {
        // Arrange
        List<String> lines = List.of(
            "2024-03-15 02:14:08 | INFO | 192.168.1.45 | /login | success"
        );

        // Act
        LogsReader.ParseResult result = LogsReader.parseLines(lines);

        // Assert
        assertEquals(1, result.validEntries().size());
        assertTrue(result.malformedLines().isEmpty());

        LogsReader.LogEntry entry = result.validEntries().get(0);
        assertEquals("INFO", entry.level());
        assertEquals("192.168.1.45", entry.sourceIp());
        assertEquals("/login", entry.target());
        assertEquals("success", entry.action());
    }

    @Test 
    void missingFieldisMalformed(){
        // Arrange
        List<String> lines = List.of(
            "2024-03-15 02:17:00 | WARN | 203.0.113.42 | /login"  // only 4 fields
        );

        // Act
        LogsReader.ParseResult result = LogsReader.parseLines(lines);

        assertEquals(1, result.malformedLines().size());
        assertTrue(result.validEntries().isEmpty());

        LogsReader.LineIssue issue = result.malformedLines().get(0);
        assertEquals(1, issue.lineNumber());
        

    }

    @Test
    void wrongDelimiter(){
        // Arrange
        List<String> lines = List.of(
            "2024-03-15 02:17:14 / INFO / 192.168.1.45 / /home / accessed"
        );

        // Act
        LogsReader.ParseResult result = LogsReader.parseLines(lines);

        // Assert
        assertEquals(1, result.malformedLines().size());
        assertTrue(result.validEntries().isEmpty());

        LogsReader.LineIssue issue = result.malformedLines().get(0);
        assertEquals(1, issue.lineNumber());
    }

    @Test 
    void wrongNoLogFields(){
         // Arrange
        List<String> lines = List.of(
            "2024-03-15 02:17:14 | Hello | INFO | 192.168.1.45 | /home | accessed"
        );

        // Act
        LogsReader.ParseResult result = LogsReader.parseLines(lines);

        // Assert
        assertEquals(1, result.malformedLines().size());
        assertTrue(result.validEntries().isEmpty());

        LogsReader.LineIssue issue = result.malformedLines().get(0);
        assertEquals(1, issue.lineNumber());
    }

    @Test 
    void badTimeStamp(){
         // Arrange
        List<String> lines = List.of(
            "not-a-timestamp | INFO | 192.168.1.45 | /home | accessed"
        );

        // Act
        LogsReader.ParseResult result = LogsReader.parseLines(lines);

        // Assert
        assertEquals(1, result.malformedLines().size());
        assertTrue(result.validEntries().isEmpty());

        LogsReader.LineIssue issue = result.malformedLines().get(0);
        assertEquals(1, issue.lineNumber());
    }

    @Test 
    void emptyLineisMalformed(){
         // Arrange
        List<String> lines = List.of(
            ""
        );

        // Act
        LogsReader.ParseResult result = LogsReader.parseLines(lines);

        // Assert
        assertEquals(1, result.malformedLines().size());
        assertTrue(result.validEntries().isEmpty());

        LogsReader.LineIssue issue = result.malformedLines().get(0);
        assertEquals(1, issue.lineNumber());
    }
}