package org.example.Classes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class LogsReader {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public record ParseResult(List<LogEntry> validEntries, List<LineIssue> malformedLines){}

    public record LogEntry(int lineNumber, String timestamp, String level, String sourceIp, String target, String action) {}

    public record LineIssue(int lineNumber, String rawContent) {}
    // used for both malformed lines and unknown patterns

    public record ScoredEntry(LogEntry entry, int severityScore) {}

    public static ParseResult parse(String filePath) throws IOException {

        Path logfilePath = Path.of(filePath);
        List<String> lines = Files.readAllLines(logfilePath);
        return parseLines(lines);
        
    }

    public static ParseResult parseLines(List<String> lines){
        List<LogEntry> validEntries = new ArrayList<>();
        List<LineIssue> malformedLines = new ArrayList<>();

        for (int i = 0; i < lines.size(); i++) {
            int lineNumber = i + 1;
            String rawLines = lines.get(i);

            // check empty
            if (rawLines.trim().isEmpty()){
                malformedLines.add( new LineIssue(lineNumber, rawLines));
                continue;
            }

            // split on | only
            String[] fields= rawLines.split("\\|", -1);

            //field count check
            if (fields.length != 5){
                malformedLines.add(new LineIssue(lineNumber, rawLines));
                continue;
            }
            //trim fields
            for (int y = 0; y < fields.length; y++){
                if (fields[y] != null) {
                    fields[y] = fields[y].trim();
                }
            }

            // try parsing field[0] as LocalDateTime with TIMESTAMP_FORMAT catch DateTimeParseException -> malformed
            
            try {
                LocalDateTime.parse(fields[0], TIMESTAMP_FORMAT);

            } catch (Exception e) {
                malformedLines.add(new LineIssue(lineNumber, rawLines));
                continue;
            }

            // build LogEntry and add to validEntries
            LogEntry entry = new LogEntry(lineNumber, fields[0], fields[1], fields[2], fields[3], fields[4]);

            validEntries.add(entry);

        }
        return new ParseResult(validEntries, malformedLines);
    }

    //Needs to retrieve the file path from the main class. It could get it from command validator class directly but the instructions are that Main Orchestrates
    //If it doesn't exist or can't be read, call the exception
    //Tracks malformed lines and also the correctly structured lines.
    //Returns both datasets to the main class.
    //How to check well structured logs:
    //Use string builder, and separate the logs where there is a delimeter |. If it doesn't exist, then the wrong delimeter was used.
    //After splitting each part of the log, check that it has all the required info.
}
