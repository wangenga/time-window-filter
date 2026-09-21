package org.example.Classes;


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

}
