package org.example;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.example.Classes.CommandValidator;
import org.example.Classes.LogsReader;
import org.example.Classes.ReportGenerator;
import org.example.Classes.RulebookAnalyzer;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {

    //Orchestrator. Hands and recieves data across classes and calls methods within each class.
    //As a user runs the program, it takes the input from the terminal and sends it to a method in CommandValidatorClass, maybe a setter method.
    //From that, the class is able to strip the command and ensure all arguments exist, and then prepares them into 3, the access log, the rulebook and the report.


    //It returns that data to main class.

    //Main then sends the access logs path to LogsReader.
    //LogsReader class reads the logs and makes sure it exists and can be read.
    //If so, it tracks and separates malformed lines from correctly structured ones.
    //It returns the correctly structured lines to MAIN class.

    //Main class then sends the data structure of correctly structured lines from the access logs to RulebookAnalyzer class.
    //It also sends it a file to the rulebook from the response it got from commandValidator.

    //Rulebook analyzer checks that the rulebook exists and can be read and then gives appropriate scores to the structured lines from the access logs.
    //It returns to main this list of structured access logs with their scores or 'Unknown patterns'


    //Main takes that data from Rulebook analyser and gives it to report generator.
    //It also sends the filepath of the report to the class.
    //ReportGenerator now reads the file path and ensures that the file can be created or written to (Updated), then using the data from rulebook analyzer, writes a report and sends it back to main
    //The report is printed.

    //Lifecycle: Main -> Command validator -> Main -> Logs reader -> Main -> Rulebook analyzer -> Main -> Report generator -> Main

    public static void main(String[] args) throws IOException {
        CommandValidator commandValidator = new CommandValidator();
        RulebookAnalyzer rulebookAnalyzer = new RulebookAnalyzer();
        //Count no. of arguments.
        if (args.length != 3){
            System.out.println("Ensure the number of arguments are 3");
            System.exit(1);
        }
        commandValidator.getArguments(args);


        if (!commandValidator.correctOrder()){
            System.exit(1);
        }

            //We hand over index 0 to LogsReader, 1 to CommandValidator and 2 to CommandValidator.
        commandValidator.getRulebookPath(args[1]);
        boolean isRulebookValid = commandValidator.validRulebook();
        //If the rulebook path is valid, then we hand it over to RulebookAnalyzer:
        if (!isRulebookValid){
            System.exit(1);
        }
        rulebookAnalyzer.getRulebookPath(args[1]);

        LogsReader.ParseResult result = null;
        try {
            result = LogsReader.parse(args[0]);
            System.out.println("Valid entries: " + result.validEntries().size());
            System.out.println("Malformed lines: " + result.malformedLines().size());

            //Converting List<LogEntry> into a List<String> and formatting the logs with a '|' delimeter
            List<String> formattedLogs = result.validEntries().stream()
                    .map(entry -> String.format("%s | %s | %s | %s | %s",
                            entry.timestamp(),
                            entry.level(),
                            entry.sourceIp(),
                            entry.target(),
                            entry.action()))
                    .toList();

            //Getting the actual line numbers for every log
            List<String> numberedFormattedLogs = result.validEntries().stream()
                    .map(entry -> String.format("Line %s: %s | %s | %s | %s | %s",
                            entry.lineNumber(), //Carries the OG line number.
                            entry.timestamp(),
                            entry.level(),
                            entry.sourceIp(),
                            entry.target(),
                            entry.action()))
                    .toList();
            //Calling the check level method:
            rulebookAnalyzer.checkLevel(formattedLogs, numberedFormattedLogs);
        } catch (IOException e) {
            System.out.println("Error reading log file: " + e.getMessage());
            System.exit(1);
        }

        //pass the logentry list into analyser directly
        rulebookAnalyzer.suspiciousIPs(result.validEntries());

        String reportText = ReportGenerator.buildReport(
            rulebookAnalyzer.getStats(),
            rulebookAnalyzer.getFlaggedEntries(),
            rulebookAnalyzer.getSuspiciousIp(),
            rulebookAnalyzer.getUnknownLogs(),
            result.malformedLines()
        );

        System.out.println("\n----- REPORT PREVIEW -----\n");
        System.out.println(reportText); 


        commandValidator.getReportPath(args[2]);
        commandValidator.writeReport(reportText);
    }

}
