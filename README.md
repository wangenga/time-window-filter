# TraceFinder
 
A command-line tool that analyses an access log, scores each entry against a configurable rulebook, and writes a report flagging what's worth a human's look.
 
Built as a Java/Maven project by  Daisy Wangenga & Gilbert Kioko.

## Usage
 
Build the jar, then run it with three file paths, in order:
 
```bash
mvn clean package
java -jar target/tracefinder.jar <logs> <rulebook> <report>
```
 
For example:
 
```bash
java -jar target/tracefinder.jar logs.txt rules.csv report.txt
```

## Architecture
 
Reading, processing, and writing are kept in separate classes. `Main` is the
only class that knows all the others exist — it orchestrates them and passes
the result of one into the next.
 
```
Main
 ├─ CommandValidator   — validates args, file existence/readability, writes the report
 ├─ LogsReader         — parses the log file into structured entries + malformed lines
 ├─ RulebookAnalyzer   — loads the rulebook, scores entries, flags, finds suspicious IPs
 └─ ReportGenerator    — formats the findings into the final report text
```

 
| Class | Responsibility |
|---|---|
| `CommandValidator` | Validates argument count/order, checks the rulebook and log files exist and are readable, writes the final report to disk |
| `LogsReader` | Parses the log file line by line into `LogEntry` records or `LineIssue` records (malformed lines) |
| `RulebookAnalyzer` | Loads `level → severity_score` from the rulebook CSV, scores each entry, tracks flagged entries, unknown patterns, activity counts, and suspicious IPs |
| `ReportGenerator` | Builds the final report text from the data the other three classes produce |
 

 ## Testing
 
Run all tests with:
 
```bash
mvn test
```
 
Tests live under `src/test/java`, one test class per class under test, and
never touch the filesystem directly — test data is built by hand inside each
test (a clean log line, a malformed one, a small rulebook string) rather than
reading real files.
 
| Test class | Covers |
|---|---|
| `LogsReaderTest` | Parsing: clean lines → structured entries; malformed lines (missing field, wrong delimiter, bad timestamp, empty) → recorded and skipped |
| `RulebookAnalyzerTest` | Rulebook loading, severity scoring, flagging, activity counts, suspicious IP detection |
| `ReportGeneratorTest` | Report text has all five sections in the right order with the right content |
| `CommandValidatorTest` | Argument validation, rulebook/log file checks, report writing |
 
## Project structure
 
```
src/
├── main/java/org/example/
│   ├── Main.java
│   ├── Classes/
│   │   ├── CommandValidator.java
│   │   ├── LogsReader.java
│   │   ├── RulebookAnalyzer.java
│   │   └── ReportGenerator.java
│   └── Exceptions/
│       └── WrongNumberOfArguments.java
└── test/java/org/example/Classes/
    ├── LogsReaderTest.java
    ├── RulebookAnalyzerTest.java
    ├── ReportGeneratorTest.java
    └── CommandValidatorTest.java
```
 