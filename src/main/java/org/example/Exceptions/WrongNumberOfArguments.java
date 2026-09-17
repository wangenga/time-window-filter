package org.example.Exceptions;

public class WrongNumberOfArguments extends RuntimeException {
    public WrongNumberOfArguments(String message) {
        super(message);
    }
}
