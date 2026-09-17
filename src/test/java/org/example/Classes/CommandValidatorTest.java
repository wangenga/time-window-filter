package org.example.Classes;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class CommandValidatorTest {

    @TempDir
    Path tempDir;

    @Test
    void correctOrder_returnsTrueForTxtCsvTxt() {
        CommandValidator validator = new CommandValidator();
        validator.getArguments(new String[]{"input.txt", "data.csv", "output.txt"});

        assertTrue(validator.correctOrder());
    }

    @Test
    void correctOrder_returnsFalseWhenFirstIsNotTxt() {
        CommandValidator validator = new CommandValidator();
        validator.getArguments(new String[]{"input.csv", "data.csv", "output.txt"});

        assertFalse(validator.correctOrder());
    }

    @Test
    void correctOrder_returnsFalseWhenSecondIsNotCsv() {
        CommandValidator validator = new CommandValidator();
        validator.getArguments(new String[]{"input.txt", "data.txt", "output.txt"});

        assertFalse(validator.correctOrder());
    }

    @Test
    void correctOrder_returnsFalseWhenThirdIsNotTxt() {
        CommandValidator validator = new CommandValidator();
        validator.getArguments(new String[]{"input.txt", "data.csv", "output.csv"});

        assertFalse(validator.correctOrder());
    }

    @Test
    void validRulebook_returnsTrueForCorrectHeaders() throws IOException {
        Path rulebook = tempDir.resolve("rules.csv");
        Files.writeString(rulebook, "level,severity_score\n1,10\n2,20\n");

        CommandValidator validator = new CommandValidator();
        validator.getRulebookPath(rulebook.toString());

        assertTrue(validator.validRulebook());
    }

    @Test
    void validRulebook_returnsTrueWhenHeadersHaveSpaces() throws IOException {
        Path rulebook = tempDir.resolve("rules_spaces.csv");
        Files.writeString(rulebook, " level , severity_score \n1,10\n");

        CommandValidator validator = new CommandValidator();
        validator.getRulebookPath(rulebook.toString());

        assertTrue(validator.validRulebook());
    }

    @Test
    void validRulebook_returnsFalseForWrongHeaders() throws IOException {
        Path rulebook = tempDir.resolve("wrong_headers.csv");
        Files.writeString(rulebook, "level,score\n1,10\n");

        CommandValidator validator = new CommandValidator();
        validator.getRulebookPath(rulebook.toString());

        assertFalse(validator.validRulebook());
    }

    @Test
    void validRulebook_returnsFalseForExtraHeaders() throws IOException {
        Path rulebook = tempDir.resolve("extra_headers.csv");
        Files.writeString(rulebook, "level,severity_score,extra\n1,10,foo\n");

        CommandValidator validator = new CommandValidator();
        validator.getRulebookPath(rulebook.toString());

        assertFalse(validator.validRulebook());
    }

    @Test
    void validRulebook_returnsFalseForEmptyFile() throws IOException {
        Path rulebook = tempDir.resolve("empty.csv");
        Files.createFile(rulebook);

        CommandValidator validator = new CommandValidator();
        validator.getRulebookPath(rulebook.toString());

        assertFalse(validator.validRulebook());
    }

    @Test
    void validRulebook_returnsFalseWhenFileDoesNotExist() {
        Path rulebook = tempDir.resolve("missing.csv");

        CommandValidator validator = new CommandValidator();
        validator.getRulebookPath(rulebook.toString());

        assertFalse(validator.validRulebook());
    }

    @Test
    void writeReport_createsNewFileWhenItDoesNotExist() throws IOException {
        Path report = tempDir.resolve("report.txt");

        CommandValidator validator = new CommandValidator();
        validator.getReportPath(report.toString());
        validator.writeReport("initial data");

        assertTrue(Files.exists(report));
        assertEquals("initial data", Files.readString(report));
    }

    @Test
    void writeReport_overwritesExistingFile() throws IOException {
        Path report = tempDir.resolve("existing_report.txt");
        Files.writeString(report, "old data");

        CommandValidator validator = new CommandValidator();
        validator.getReportPath(report.toString());
        validator.writeReport("new data");

        assertTrue(Files.exists(report));
        assertEquals("new data", Files.readString(report));
    }

    @Test
    void writeReport_throwsWhenExtensionIsNotTxt() {
        Path report = tempDir.resolve("report.md");

        CommandValidator validator = new CommandValidator();
        validator.getReportPath(report.toString());

        assertThrows(IllegalArgumentException.class,
                () -> validator.writeReport("data"));
    }

    @Test
    void writeReport_throwsWhenReportPathIsNull() {
        CommandValidator validator = new CommandValidator();

        assertThrows(IllegalArgumentException.class,
                () -> validator.writeReport("data"));
    }

    @Test
    void writeReport_throwsWhenReportPathIsBlank() {
        CommandValidator validator = new CommandValidator();
        validator.getReportPath("   ");

        assertThrows(IllegalArgumentException.class,
                () -> validator.writeReport("data"));
    }

    @Test
    void writeReport_acceptsUppercaseTxtExtension() throws IOException {
        Path report = tempDir.resolve("REPORT.TXT");

        CommandValidator validator = new CommandValidator();
        validator.getReportPath(report.toString());
        validator.writeReport("data");

        assertTrue(Files.exists(report));
        assertEquals("data", Files.readString(report));
    }
}