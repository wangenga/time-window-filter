package org.example.Classes;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;


public class RulebookAnalyzer {
    //Ensures rulebook can be accessed and read, else calls the exception

    //Recieves the dataset of well structured lines from the logs
    //Compares each line against the rulebook
    //Gives each line a score and stores that info in a dataset. eg a multidimensional array or sth
    //Hands this data to the main class.

    //CORRECTLY STRUCTURED LOGS HAVE 4 DELIMETERS. I NEED THE CHARACTERS BETWEEN DELIMETER 1 AND 2.
    List<Map.Entry<String, Integer>> flaggedLogs = new ArrayList<>();
    List<String> unknownLogs = new ArrayList<>();
    List<String> flaggedIpsList = new ArrayList<>();
    Set<String> flaggedIPsUnique = new HashSet<>(); //Uniquely stores IP Addresses that have been flagged. We will then use that dataset to see how many times...
    //...each of these records appears in flagged logs.
    Map<String, Integer> flaggedIPsCount = new HashMap<>();
    Map<String, Integer> stats = new HashMap<>();

    Map<String, Integer> rulebookContent = new HashMap<>();


    String rulebookPath;
    public void getRulebookPath(String path) {
        rulebookPath = path;
        readRulebook();
        //READ EVERY LINE, STORE THE VALUES IN A MAP.
        //COMPARE EVERY LOG TO THE KEYS, BY LOOPING THROUGH THE MAP PERHAPS
        // IF A LOG'S SEVERITY EXISTS, AS A KEY, THEN WE CHECK THE VALUE ATTACHED TO THAT KEY.
        //IF THE VALUE >= 3, THE LOG IS FLAGGED.

        //ELSE IF A LOG'S SEVERITY DOES NOT EXIST AS A KEY, THEN WE MARK IT AS UNKNOWN.
        //I THINK THE REST OF THE LOGIC IS SAME
    }

    public void readRulebook() {
        rulebookContent.clear();

        if (rulebookPath == null || rulebookPath.isBlank()) {
            throw new IllegalArgumentException("Rulebook path has not been set.");
        }

        try (BufferedReader br = new BufferedReader(new FileReader(rulebookPath))) {

            // 1. Read and validate header
            String header = br.readLine();
            if (header == null) {
                System.out.println("Rulebook is empty.");
                return;
            }

            List<String> expectedHeaders = Arrays.asList("level", "severity_score");
            List<String> actualHeaders = Arrays.stream(header.split(","))
                    .map(String::trim)
                    .toList();

            if (!expectedHeaders.equals(actualHeaders)) {
                throw new IllegalArgumentException(
                        "Rulebook headers must be 'level,severity_score'. Found: " + actualHeaders);
            }

            // 2. Read each row and put into the map
            String line;
            int lineNumber = 1; // header was line 1
            while ((line = br.readLine()) != null) {
                lineNumber++;

                if (line.isBlank()) continue; // skip empty lines

                String[] parts = line.split(",");
                if (parts.length < 2) {
                    System.out.println("Skipping malformed line " + lineNumber + ": " + line);
                    continue;
                }

                String level = parts[0].trim();
                String scoreStr = parts[1].trim();

                try {
                    int severityScore = Integer.parseInt(scoreStr);
                    rulebookContent.put(level, severityScore);
                } catch (NumberFormatException e) {
                    System.out.println("Skipping line " + lineNumber
                            + " — severity_score is not a number: " + scoreStr);
                }
            }
        } catch (IOException e) {
            System.out.println("Could not read rulebook at " + rulebookPath);
            e.printStackTrace();
        }
    }

    public void checkLevel(List<String> validEntries, List<String> numberedValidEntries) {

        for (int i = 0; i < validEntries.size(); i++) {
            String currentLog = validEntries.get(i);

            int delimeter1Index = currentLog.indexOf("|");
            int delimeter2Index = currentLog.indexOf("|", delimeter1Index + 1);

            String severity = currentLog.substring(delimeter1Index + 1, delimeter2Index).trim();
            if (rulebookContent.containsKey(severity)) {
                // Count EVERY known severity, whatever its name
                stats.merge(severity, 1, Integer::sum); //increment the count for severity by 1, creating it at 1 if it doesn't exist yet.

                int score = rulebookContent.get(severity);
                if (score >= 3) {
                    flaggedLogs.add(Map.entry(currentLog, score));
                }
            } else {
                unknownLogs.add(numberedValidEntries.get(i));
            }

        }
    }

        //accepts list of valid enties from logreader
        public void suspiciousIPs (List<LogsReader.LogEntry> validEntries) {
            for (Map.Entry<String, Integer> entry : flaggedLogs) {
                String flaggedLog = entry.getKey();
                int d1 = flaggedLog.indexOf("|");
                int d2 = flaggedLog.indexOf("|", d1 + 1);
                int d3 = flaggedLog.indexOf("|", d2 + 1);

                String flaggedIP = flaggedLog.substring(d2 + 1, d3).trim();
                //We add the IP adresses to a normal list and to a unique list, and count how many times a unique record appears:
                //**Probably not the most optimal solution.
                flaggedIPsUnique.add(flaggedIP);
            }

            for (LogsReader.LogEntry log : validEntries) {
                //the valid entries are already parsed
                String ip = log.sourceIp();
                if (flaggedIPsUnique.contains(ip)) {
                    flaggedIPsCount.merge(ip, 1, Integer::sum);
                }
                
            }

        }

        public Map<String, Integer> getStats() {
            Map<String, Integer> sorted = stats.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .collect(java.util.stream.Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue,
                            (a, b) -> a,
                            LinkedHashMap::new   // preserves sorted order
                    ));

            return sorted;
        }

        public Map<String, Integer> getSuspiciousIp () {
            Map<String, Integer> sortedFlaggedIPsCount = flaggedIPsCount.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .collect(java.util.stream.Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue,
                            (oldValue, newValue) -> oldValue, // Merge function (not needed here but required by syntax)
                            LinkedHashMap::new                // Guarantees the sorted order is kept
                    ));

            return sortedFlaggedIPsCount;
        }

        public List<String> getFlaggedEntries () {
            return flaggedLogs.stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .map(Map.Entry::getKey)
                .toList();
        }
        public List<String> getUnknownLogs () {
            return unknownLogs;
        }
    }

