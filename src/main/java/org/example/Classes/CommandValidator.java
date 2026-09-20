package org.example.Classes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;

public class CommandValidator {


    public record Config(String logPath, String rulesPath, String reportPath, TimeWindow window) {}

    private static final String USAGE =
        "Usage: java -jar tracefinder.jar <logs> <rules.csv> <report>"
        + " [\"yyyy-MM-dd HH:mm:ss\" \"yyyy-MM-dd HH:mm:ss\"]";

    public static Config parse(String[] args){
        //Count no. of arguments.
        if (args.length != 3 && args.length != 5){
            throw new IllegalArgumentException(
                "Expected 3 or 5 arguments but got " + args.length + ".\n" + USAGE);
        }


        TimeWindow window = null;

        if (args.length == 5){
            LocalDateTime start = parseTimeStamp(args[3], "start");
            LocalDateTime end = parseTimeStamp(args[4], "end");
            window = new TimeWindow(start, end);
        }

        return new Config(args[0], args[1], args[2], window);
    }

    private static LocalDateTime parseTimeStamp(String text, String which) {
        try {
            return  LocalDateTime.parse(text.trim(), LogsReader.FORMAT);
        } catch (DateTimeParseException e){
            throw new IllegalArgumentException(
                "Invalid " + which + " time \"" + text + "\". Expected format: yyyy-MM-dd HH:mm:ss");
        }
    }


    String report;
    public void getReportPath (String path){
        System.out.println("The report path is " + path);
        report = path;
    }

    /**
     * Checks that `report` is a valid .txt path, creates it if missing,
     * or overwrites it with `newData` if it already exists.
     */
    public void writeReport(String newData) throws IOException {
        if (report == null || report.isBlank()) {
            throw new IllegalArgumentException("Report path has not been set.");
        }

        // 1. Validate format: must end with .txt (case-insensitive)
        if (!report.toLowerCase().endsWith(".txt")) {
            throw new IllegalArgumentException(
                    "Invalid report format. Path must end with .txt: " + report);
        }

        Path path = Paths.get(report);

        // If file exists -> overwrite. If not -> create.
        if (Files.exists(path)) {
            // Overwrite by truncating and writing
            Files.writeString(path, newData,
                    StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            System.out.println("Report updated: " + path.toAbsolutePath());
        } else {
            Files.writeString(path, newData,
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
            System.out.println("Report created: " + path.toAbsolutePath());
        }
    }
}
