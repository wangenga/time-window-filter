package org.example.Classes;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;


public class RulebookAnalyzer {

    private static final List<String> EXPECTED_HEADERS = Arrays.asList("level", "severity_score");
    private static final int FLAG_THRESHOLD = 3;

    List<LogsReader.ScoredEntry> flaggedLogs = new ArrayList<>();
    List<LogsReader.LogEntry> unknownLogs = new ArrayList<>();
    List<String> flaggedIpsList = new ArrayList<>();
    Set<String> flaggedIPsUnique = new HashSet<>(); //Uniquely stores IP Addresses that have been flagged. We will then use that dataset to see how many times...
    //...each of these records appears in flagged logs.
    Map<String, Integer> flaggedIPsCount = new HashMap<>();
    Map<String, Integer> stats = new LinkedHashMap<>();

    Map<String, Integer> rulebookContent = new LinkedHashMap<>();


    String rulebookPath;
    public void loadRulebook(String path) {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("Rulebook path has not been set.");
        }

        Path p = Path.of(path);
        if (!Files.exists(p)) {
            throw new IllegalArgumentException("Rulebook not found: " + path);
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(p);
        } catch (IOException e) {
            throw new IllegalArgumentException(
                "Cannot read rulebook " + path + ": " + e.getMessage());
        }
        parseRulebook(lines, path);

    }

    public void parseRulebook(List<String> lines, String path) {
        rulebookContent.clear();
        stats.clear();

        if (lines.isEmpty()) {
            throw new IllegalArgumentException("Rulebook " + path + " is empty.");
        }

        List<String> headers = Arrays.stream(lines.get(0).split(",", -1))
                    .map(String::trim)
                    .toList();

        if (!EXPECTED_HEADERS.equals(headers)) {
            throw new IllegalArgumentException("Rulebook " + path
                + " must have the header 'level,severity_score' but found: " + headers);
        }
        
        for (int i = 1; i < lines.size(); i++){
            String line = lines.get(i);
            int lineNumber = i + 1;

            if (line.isBlank()) continue;

            String [] parts = line.split(",", -1);
            if (parts.length != 2){
                throw new  IllegalArgumentException("RuleBook " + path + ", line " + lineNumber
                + ": expected 2 columns but found " + parts.length + ": " + line);
            } 
            try {
                rulebookContent.put(parts[0].trim(), Integer.parseInt(parts[1].trim()));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Rulebook " + path + ", line " + lineNumber
                    + ": severity_score is not a number: " + parts[1].trim());
            }
        }
        //every level the ruleBook defines appears in the summary, even with 0 entries
        rulebookContent.keySet().forEach(level -> stats.put(level, 0));
            
    }

    public void checkLevel(List<LogsReader.LogEntry> validEntries) {

        for (LogsReader.LogEntry entry : validEntries) {
            Integer score = rulebookContent.get(entry.level());

            if (score == null){
                unknownLogs.add(entry);
                continue;
            }
            stats.merge(entry.level(), 1, Integer::sum);
            if (score >= FLAG_THRESHOLD) {
                flaggedLogs.add(new LogsReader.ScoredEntry(entry, score)); 
            }
        }
    }

    //accepts list of valid enties from logreader
    public void suspiciousIPs (List<LogsReader.LogEntry> validEntries) {
        for (LogsReader.ScoredEntry scored : flaggedLogs) {
            //Now this is the most optimal solution
            flaggedIPsUnique.add(scored.entry().sourceIp());
        }

        for (LogsReader.LogEntry log : validEntries) {
            //the valid entries are already parsed
            String ip = log.sourceIp();
            if (flaggedIPsUnique.contains(ip)) {
                flaggedIPsCount.merge(ip, 1, Integer::sum);
            }
                
        }

    }

    //Results

    public Map<String, Integer> getStats() {
        return new LinkedHashMap<>(stats);
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
            .sorted(Comparator.comparingInt(LogsReader.ScoredEntry::severityScore).reversed())
            .map(scored -> scored.entry().rawline())
            .toList();
    }
        
    public List<String> getUnknownLogs () {
        return unknownLogs.stream()
            .map(entry -> "Line " + entry.lineNumber() + ": " + entry.rawline())
            .toList();
    }
}