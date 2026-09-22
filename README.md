# TraceFinder — Time Window Filter
 
TraceFinder analyses an access log against a rulebook and writes a report flagging what's worth a human's look. This build adds an optional time window: instead of always analysing the whole file, the tool can be pointed at a specific slice of time.

## Prerequisites
 
- **Java 21** (or later). The project targets an LTS release; `pom.xml` pins `maven.compiler.release` to 21 so the build stays compatible with JaCoCo regardless of which JDK is installed locally.
- **Maven 3.9+**, used to build, run tests, and fetch dependencies (JUnit, JaCoCo) automatically — nothing needs to be installed by hand.

## Usage
 
Build and package:
 
```
mvn clean package
```
 
This produces the runnable jar under `target/`.
 
## Running the tool
 
```
# whole file
java -jar tracefinder.jar logs.txt rules.csv report.txt
 
# only entries in this window
java -jar tracefinder.jar logs.txt rules.csv report.txt "2024-03-15 02:00:00" "2024-03-15 03:30:00"
```

- 3 arguments analyses the entire file, same as before.
- 5 arguments adds a start and end timestamp, in the same format the log uses (`yyyy-MM-dd HH:mm:ss`).
- Any other number of arguments stops the tool with a usage message and a non-zero exit code.
**The window is start inclusive, end exclusive.** An entry stamped exactly at the start is inside the window. An entry stamped exactly at the end is not. A window whose start equals its end is valid and holds nothing. This follows the convention most languages and API guidelines use for time ranges ([Google AIP-145](https://google.aip.dev/145)).

## Architecture
 
Reading, processing, and writing are kept in separate classes. `Main` is the
only class that knows all the others exist — it orchestrates them and passes
the result of one into the next.
 
```
Main
 ├─ CommandValidator.parse(args)      → Config (paths + optional TimeWindow)
 ├─ RulebookAnalyzer.loadRulebook()   → level → severity_score map
 ├─ LogsReader.parse()                → valid entries + malformed lines
 ├─ TimeWindow.filter(entries, window)→ entries inside the window
 ├─ RulebookAnalyzer.checkLevel() / .suspiciousIPs()  → findings
 └─ ReportGenerator.buildReport() + .writeReport()    → report.txt
```
 
| Class | Job |
|---|---|
| `CommandValidator` | Turns `String[]` into a `Config` (paths + `TimeWindow`), or throws with a readable message. Never touches a file. |
| `LogsReader` | Reads the log file and parses each line into a `LogEntry` or a `LineIssue` (malformed). Owns the shared timestamp `FORMAT`. |
| `TimeWindow` | The window itself (`start`, `end`), `contains(timestamp)`, `filter(entries, window)`, and `describe(window)` for the report header. A `null` window means "no filtering — whole file." |
| `RulebookAnalyzer` | Loads and parses the rulebook, matches entries against it, flags, groups by IP, and produces the four findings. |
| `ReportGenerator` | Formats the five report sections and writes the file. |
| `Main` | Orchestrates the above, catches every stop-the-tool failure in one place, and exits non-zero. |

## Edge cases hunted, and why each is worth a test
 
The real risk in this feature isn't the common path, it's the boundary. All of these are covered in `TimeWindowTest`, `RulebookAnalyzerTest`, or `ReportGeneratorTest`.
 
| Case | Why it matters |
|---|---|
| Entry exactly at the start timestamp | Must be **included** — classic off-by-one, and the spec calls it out explicitly. |
| Entry exactly at the end timestamp | Must be **excluded** — the other half of the same off-by-one. |
| Entry one second before start / one second before end | Confirms the boundary is exact to the second, not approximate. |
| Start equals end | Valid window, holds nothing — even the instant itself is excluded. Easy to wrongly special-case or wrongly include. |
| Start after end | Must stop the tool with a message saying the start is later than the end. |
| Start one second after end | Tests that the validation boundary itself is exact. |
| Window with nothing inside it (falls between two clusters of entries) | Every finding must still be produced, each section showing "None found." |
| Window entirely before or entirely after the log | Same as above, approached from both directions — guards against an implementation that assumes the window overlaps the log. |
| Window covering the entire log | Should behave identically to giving no window at all (aside from the header text). |
| Malformed line inside the window's time range | Still recorded — malformed lines have no valid timestamp, so "inside the window" doesn't apply to them; they're always reported. |
| Malformed line outside the window's time range | Still recorded, for the same reason — the window must never hide a malformed line. |
| Unknown-level entry inside vs. outside the window | Included or excluded exactly like any other entry, and keeps its **original** line number from the file either way. |
| Line numbers after earlier entries are filtered out | Numbering must never shift — a flagged or unknown entry always cites its real position in the source file. |
| An IP with entries both inside and outside the window | Its listed total must count only the in-window entries, not its total across the whole file. |
| An IP whose only flagged (severity ≥ 3) entry is outside the window | It must **not** appear as suspicious — being flagged elsewhere in the file doesn't count. |
| Out-of-order log (a later timestamp appears before an earlier one) | The filter must not assume the file is sorted, or stop scanning early and miss an in-window entry that comes after an out-of-window one. |
| Argument counts of 0, 1, 2, 4, 6 | Only 3 and 5 are valid; everything else stops with a usage message. |
| Unparseable start / unparseable end / an impossible date (`2024-02-30`) / wrong format | Each stops the tool cleanly, and the message says which of the two (start or end) was the problem. |
| `Time Window:` header text, with and without a window | Must read `Time Window: <start> to <end>` or `Time Window: full file`, directly under `Generated:`, matching the spec's example layout exactly. |

 ## Testing
 
Run all tests with:
 
```bash
mvn test
```
 
Tests build their data by hand — a few hand-written lines or entries — and none of the logic tests open, read, or write a file, per the project rules.
The two exceptions are noted below.
 
| Test class | Covers |
|---|---|
| `CommandValidatorTest` | Argument count, window construction from args 4/5, bad timestamps, start-after-end, names-don't-matter. |
| `TimeWindowTest` | `contains` boundaries, constructor validation, `filter`, `describe`, all the window edge cases above. |
| `RulebookAnalyzerTest` | Rulebook parsing (header, malformed rows), level matching (known / unknown / case-sensitivity), counting, flagging, IP grouping, and the same edge cases re-run through the window filter. |
| `ReportGeneratorTest` | Header format (with and without a window), section order, "None found" placeholders, raw-line and ordering fidelity. |
| `LogsReaderTest` | Line parsing: clean lines, each malformed case (missing field, wrong delimiter, bad timestamp, empty line), line numbering. |
 
**Two test classes touch the filesystem on purpose, using `@TempDir`:**
 
- `LogsReaderTest` — confirms reading a real, nonexistent, and correctly read file behaves as expected.
- `ReportGeneratorWriteTest` — confirms `writeReport` creates a new file, overwrites an existing one completely, and fails clearly on a missing parent folder or a blank path.

These are kept separate from the logic tests intentionally. They exercise real I/O paths (create vs. overwrite, missing directories) that can't be verified without a filesystem, and were treated as being in the same spirit as the project's earlier I/O-adjacent tests rather than as "logic" tests.
