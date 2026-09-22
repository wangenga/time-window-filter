package org.example.Classes;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReportGeneratorWriteTest {

    @TempDir Path tempDir;

    @Test
    void writeReport_createsNewFileWhenItDoesNotExist() throws IOException {
        Path report = tempDir.resolve("report.txt");
        ReportGenerator.writeReport(report.toString(), "initial data");
        assertEquals("initial data", Files.readString(report));
    }

    @Test
    void writeReport_overwritesExistingFileCompletely() throws IOException {
        Path report = tempDir.resolve("existing_report.txt");
        Files.writeString(report, "old data that is longer than the new data");
        ReportGenerator.writeReport(report.toString(), "new data");
        assertEquals("new data", Files.readString(report));
    }

    @Test
    void writeReport_nullPath_throws() {
        assertThrows(IllegalArgumentException.class, () -> ReportGenerator.writeReport(null, "data"));
    }

    @Test
    void writeReport_blankPath_throws() {
        assertThrows(IllegalArgumentException.class, () -> ReportGenerator.writeReport("   ", "data"));
    }

    @Test
    void writeReport_anyExtensionIsAccepted() throws IOException {
        Path report = tempDir.resolve("report.out");
        ReportGenerator.writeReport(report.toString(), "data");
        assertTrue(Files.exists(report));
    }

    @Test
    void writeReport_missingParentFolder_throwsIOExceptionNamingThePath() {
        Path report = tempDir.resolve("no-such-dir").resolve("report.txt");
        IOException e = assertThrows(IOException.class, () -> ReportGenerator.writeReport(report.toString(), "data"));
        assertTrue(e.getMessage().contains("Cannot write report to"));
    }
}