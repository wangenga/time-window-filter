package org.example.Classes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

public class ReportGenerator {
   //Recieves data of each log and its score from main
    //Generates a report.
    //Checks if the output path can be created or written to.
    //If it cant, call an exception that kills the program.
    //Returns this report to the main class.

    private static final DateTimeFormatter REPORT_TIMESTAMP_FORMAT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static String buildReport(
        LocalDateTime generatedAt,
        TimeWindow window,
        Map<String, Integer> activitySummary,
        List<String> flaggedEntries,
        Map<String, Integer> susIp,
        List<String> unknownlogs,
        List<LogsReader.LineIssue> malformedLines
    ){
        StringBuilder sb = new StringBuilder();

        sb.append("=== Log Analysis Report ===\n");
        sb.append("Generated: ").append(generatedAt.format(REPORT_TIMESTAMP_FORMAT)).append("\n");
        sb.append(TimeWindow.describe(window)).append("\n\n");

        sb.append("--- Activity Summary ---\n");
        if (activitySummary.isEmpty()){
            sb.append("None found\n");
        } else {
            for (Map.Entry<String, Integer> entry : activitySummary.entrySet()){
                sb.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
            }
        }
        sb.append("\n");

        sb.append("--- Flagged Entries ---\n");
        if (flaggedEntries.isEmpty()){
            sb.append("None found \n");
        }else {
            for (String flaggedlog : flaggedEntries) {
                sb.append(flaggedlog).append('\n');
            }
        }
        sb.append("\n");

        sb.append("--- Suspicious Activity by IP ---\n");
        if (susIp.isEmpty()){
            sb.append("None found\n");
        }else {
            for (Map.Entry<String, Integer> entry : susIp.entrySet()){
                sb.append(entry.getKey()).append(": ").append(entry.getValue()).append(" entries").append("\n");  
            }
        }
        sb.append("\n");

        sb.append("--- Unknown Patterns ---\n");
        if (unknownlogs.isEmpty()){
            sb.append("None found\n");
        }else {
            for (String unknown : unknownlogs){
                sb.append(unknown).append("\n");
            }
        }
        sb.append("\n");

        sb.append("--- Malformed Lines ---\n");
        if (malformedLines.isEmpty()){
            sb.append("None found\n");
        }else {
                for (LogsReader.LineIssue issue : malformedLines){
                    sb.append("Line ").append(issue.lineNumber()).append(": ").append(issue.rawContent()).append("\n");
                }
            }

        return sb.toString();

    }
    public static void writeReport(String reportPath, String content) throws IOException {
        if (reportPath == null || reportPath.isBlank()) {
            throw new IllegalArgumentException("Report path has not been set.");
        }

        try {
            Files.writeString(Path.of(reportPath), content);
        }catch (IOException e) {
            throw new IOException("Cannot write report to " + reportPath + ": " + e.getMessage(), e);
        }
        
    }
}
