package org.example.Classes;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.List;

public class CommandValidator {
    //Main class calls this class file.
    //Its workflow is that it takes the command, cleans it, and ensures that 3 files are part of the argument.
    // If there are problems, relevant exceptions are called.
    // If no problem, it has a method to return the 3 file names to the main class.

    String [] paths = new String[3];
    public void getArguments (String[] arguments){
        paths = arguments;
    }

    //Ensure the correct order of the 3 files: .txt, .csv and .txt
    public boolean correctOrder (){
        if (paths[0].endsWith(".txt") && paths[1].endsWith(".csv") && paths[2].endsWith(".txt")){
            System.out.println("Correct order");
            return true;
        }
        else {
            System.out.println("Ensure the correct order, txt, csv, txt");
            return false;
        }
    }

    String ruleBook;
    public void getRulebookPath (String path){
        System.out.println("The rulebook path is " + path);
        ruleBook = path;
    }


    //Check if rulebook exists and has expected columns
    public boolean validRulebook (){
        if (Files.exists(Paths.get(ruleBook))){
            //Expected columns:
            List<String> expectedHeaders = Arrays.asList("level", "severity_score");

            try (BufferedReader br = new BufferedReader(new FileReader(ruleBook))){
                String header = br.readLine();

                if(header != null){
                    List<String> actualHeaders = Arrays.stream(header.split(","))
                            .map(String::trim)
                            .toList();

                    if (expectedHeaders.equals(actualHeaders)){
                        System.out.println("Nice! The rulebook has correct headers: " + actualHeaders);
                        return true;
                    }
                    else {
                        System.out.println("The column names/headers of this file do not match what is expected!!");
                        return false;
                    }
                }
                else {
                    System.out.println("This csv file is empty!!");
                    return false;
                }
            } catch (IOException e){
                e.printStackTrace();
                return false;
            }
        }
        else{
            System.out.println("This rulebook does not exist.");
            return false;
        }
    }

    public String setRulebookPath (){
        return ruleBook;
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
