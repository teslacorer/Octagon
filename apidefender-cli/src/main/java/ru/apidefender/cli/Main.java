package ru.apidefender.cli;

import picocli.CommandLine;
import ru.apidefender.cli.commands.ScanCommand;

public class Main {
    public static void main(String[] args) {
        int exit = new CommandLine(new Root()).addSubcommand("scan", new ScanCommand()).execute(args);
        System.exit(exit);
    }

    @CommandLine.Command(name = "apidefender", mixinStandardHelpOptions = true, version = "0.1.0",
            description = "CLI для аудита API (OpenAPI + OWASP)")
    static class Root implements Runnable {
        @Override public void run() { System.out.println("Используйте подкоманду: scan"); }
    }
}

