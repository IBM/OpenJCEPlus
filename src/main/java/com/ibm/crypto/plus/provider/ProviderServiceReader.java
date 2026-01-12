/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A class to read and parse Provider.Service definitions from a file.
 * 
 * This class reads files containing putService() calls in the format:
 * putService(new OpenJCEPlusService(provider, "Type", "Algorithm", "ClassName", aliases));
 * 
 * Example usage:
 * <pre>
 * ProviderServiceReader reader = new ProviderServiceReader("services.txt");
 * List<ServiceDefinition> services = reader.readServices();
 * for (ServiceDefinition service : services) {
 *     System.out.println(service.getType() + ": " + service.getAlgorithm());
 * }
 * </pre>
 */
public class ProviderServiceReader {
    
    private String filePath = null;
    private String name;
    private String description;
    private static final Pattern PUT_SERVICE_PATTERN = Pattern.compile(
        "putService\\s*\\(\\s*new\\s+\\w+Service\\s*\\([^,]+,\\s*\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\"",
        Pattern.DOTALL
    );
    private BufferedReader reader = null;
    
    /**
     * Represents a single service definition parsed from the file.
     */
    public static class ServiceDefinition {
        private final String type;
        private final String algorithm;
        private final String className;
        private final List<String> aliases;
        private final Map<String, String> attributes;
        private final int lineNumber;

        
        public ServiceDefinition(String type, String algorithm, String className, 
                               List<String> aliases, Map<String, String> attributes, int lineNumber) {
            this.type = type;
            this.algorithm = algorithm;
            this.className = className;
            this.aliases = aliases != null ? new ArrayList<>(aliases) : new ArrayList<>();
            this.attributes = attributes != null ? new HashMap<>(attributes) : new HashMap<>();
            this.lineNumber = lineNumber;
        }
        
        public String getType() {
            return type;
        }
        
        public String getAlgorithm() {
            return algorithm;
        }
        
        public String getClassName() {
            return className;
        }
        
        public List<String> getAliases() {
            return new ArrayList<>(aliases);
        }
        
        public Map<String, String> getAttributes() {
            return new HashMap<>(attributes);
        }
        
        public int getLineNumber() {
            return lineNumber;
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("ServiceDefinition[line=").append(lineNumber)
              .append(", type=").append(type)
              .append(", algorithm=").append(algorithm)
              .append(", className=").append(className);
            if (!aliases.isEmpty()) {
                sb.append(", aliases=").append(aliases);
            }
            if (!attributes.isEmpty()) {
                sb.append(", attributes=").append(attributes);
            }
            sb.append("]");
            return sb.toString();
        }
    }
    
    /**
     * Creates a new ProviderServiceReader for the specified file.
     * 
     * @param filePath the path to the file containing service definitions
     */
    public ProviderServiceReader(String filePath) {
        this.filePath = filePath;
    }
   
    /**
     * Creates a new ProviderServiceReader for the specified file.
     * 
     * @param filePath the path to the file containing service definitions
     */
    public ProviderServiceReader(BufferedReader br) {
        this.reader = br;
    }

    /**
     * Reads and parses all service definitions from the file.
     * 
     * @return a list of ServiceDefinition objects
     * @throws IOException if an I/O error occurs reading the file
     */
    public List<ServiceDefinition> readServices() throws IOException {
        List<ServiceDefinition> services = new ArrayList<>();
        BufferedReader rd = null;

        System.out.println("file path = " + filePath);

        try {
            if (filePath == null && this.reader == null) {
                throw new IOException("No file specified"); 
            } else if (null == filePath && this.reader != null) {
                rd = this.reader;
            } else if (filePath != null && !Files.exists(Paths.get(filePath))) { 
                throw new IOException("File not found: " + filePath);  
            } else {
                // this filePath != null && Files.exists(Paths.get(filePath))
                rd = new BufferedReader(new FileReader(filePath));
            }     
        } catch (Exception e) {
            throw new IOException("File issue: " + e.getMessage());
        } 
        
        try {
            String line;
            int lineNumber = 0;
            StringBuilder currentStatement = new StringBuilder();
            int statementStartLine = 0;
            int type = 0;
            List<String> aliases = null;
            Map<String, String> attributes = new HashMap();
            
            while ((line = rd.readLine()) != null) {
                lineNumber++;
                String trimmedLine = line.trim();
                
                // Skip empty lines and comments
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("//") || trimmedLine.startsWith("/*")) {
                    continue;
                }

                // Check if this line starts a putService call
                if (trimmedLine.contains("putService(")) {
                    currentStatement = new StringBuilder(trimmedLine);
                    statementStartLine = lineNumber;
                    type = 1;
                }
                
                // Check if this line starts a aliases call
                if (trimmedLine.contains("aliases =")) {
                    currentStatement = new StringBuilder(trimmedLine);
                    statementStartLine = lineNumber;
                    type = 2;
                }
                
                // Check if this line starts a attrs.put call
                if (trimmedLine.contains("attrs.put(")) {
                    currentStatement = new StringBuilder(trimmedLine);
                    statementStartLine = lineNumber;
                    type = 3;
                }
                
                // Check if this line starts a putService call
                if (trimmedLine.contains("name =")) {
                    currentStatement = new StringBuilder(trimmedLine);
                    statementStartLine = lineNumber;
                    type = 4;
                }
                
                // Check if this line starts a putService call
                if (trimmedLine.contains("descrption =")) {
                    currentStatement = new StringBuilder(trimmedLine);
                    statementStartLine = lineNumber;
                    type = 5;
                }
                
                // Accumulate the statement
                if (currentStatement.length() > 0) {
                    if (currentStatement.toString().compareTo(trimmedLine) != 0) {
                        currentStatement.append(" ").append(trimmedLine);
                    }

                    // Check if statement is complete (ends with semicolon)
                    if (trimmedLine.endsWith(";")) {
                        switch(type) {
                            case 1:
                                ServiceDefinition service = parseServiceDefinition(
                                    currentStatement.toString(), statementStartLine, aliases, attributes);
                                if (service != null) {
                                    services.add(service);
                                    aliases = null;
                                    attributes.clear();
                                }
                                break;    
                            case 2:
                                aliases = parseAliases(currentStatement.toString());
                                break;
                            case 3:
                                parseAttributes(attributes, currentStatement.toString());
                                break;
                            case 4:
                                name = parseString(currentStatement.toString());
                                break;
                            case 5:
                                description =  parseString(currentStatement.toString());
                                break;
                        }
                        type = 0;
                        currentStatement = new StringBuilder();
                    }
                }
            }
        } catch (Exception e) {
            throw new IOException("Error reading config. file", e.getCause());
        }
       
        return services;
    }
    
    /**
     * Parses a single putService statement into a ServiceDefinition.
     * 
     * @param statement the complete putService statement
     * @param lineNumber the line number where the statement starts
     * @return a ServiceDefinition object, or null if parsing fails
     */
    private ServiceDefinition parseServiceDefinition(String statement, int lineNumber, List<String> aliases, Map<String, String> attributes) {
        Matcher matcher = PUT_SERVICE_PATTERN.matcher(statement);
        
        if (!matcher.find()) {
            return null;
        }
        
        String type = matcher.group(1);
        String algorithm = matcher.group(2);
        String className = matcher.group(3);
      
        return new ServiceDefinition(type, algorithm, className, aliases, attributes, lineNumber);
    }
    
    /**
     * Parses the aliases array from a putService statement.
     * 
     * @param statement the putService statement
     * @return a list of alias strings
     */
    private List<String> parseAliases(String statement) {
        List<String> aliases = new ArrayList<>();
        
        // Look for aliases = new String[] { ... } pattern
        Pattern aliasPattern = Pattern.compile(
            "aliases\\s*=\\s*new\\s+String\\s*\\[\\s*\\]\\s*\\{([^}]+)\\}",
            Pattern.DOTALL
        );
        Matcher matcher = aliasPattern.matcher(statement);
        
        if (matcher.find()) {
            String aliasContent = matcher.group(1);
            // Split by comma and extract quoted strings
            Pattern quotedString = Pattern.compile("\"([^\"]+)\"");
            Matcher quoteMatcher = quotedString.matcher(aliasContent);
            while (quoteMatcher.find()) {
                aliases.add(quoteMatcher.group(1));
            }
        }
        
        return aliases;
    }
    
    /**
     * Parses the string to remove quotes and continuation chars
     * 
     * @param statement the name = or description = statements
     * @return a string
     */
    private String parseString(String statement) {
        String str = null;
     
        Pattern pattern = Pattern.compile("=\\s*(\"[^\"]*\"(?:\\s*\\+\\s*\"[^\"]*\")*)", Pattern.DOTALL);
        Matcher matcher = pattern.matcher(statement);
        if (matcher.find()) {
            str = matcher.group(1);
            str = str.replaceAll("\"\\s*\\+\\s*\"", "");  // Remove " + " between strings
            str = str.replaceAll("\"", "");
            str = str.replaceAll("\\\\n", "\n");  // Replace \n with newline
        }
        
        return str;
    }

    /**
     * Parses attributes from a putService statement.
     * 
     * @param statement the putService statement
     * @return a map of attribute key-value pairs
     */
    private void parseAttributes(Map<String, String> attributes, String statement) {
        // The regex pattern
        String regex = "attrs\\.put\\(\"([^\"]+)\",\\s*([a-zA-Z_][a-zA-Z0-9_]*|\"[^\"]+(?:\"\\s*\\+\\s*\"[^\"]+)*\")\\);";
        Pattern pattern = Pattern.compile(regex);
        
        // Process each input

        Matcher matcher = pattern.matcher(statement);
        if (matcher.find()) {
            String attributeName = matcher.group(1);
            String value = matcher.group(2);
            attributes.put(attributeName, value);
        }

        return;
    }
    
    /**
     * Filters services by type.
     * 
     * @param services the list of services to filter
     * @param type the service type to filter by
     * @return a list of services matching the specified type
     */
    public static List<ServiceDefinition> filterByType(List<ServiceDefinition> services, String type) {
        List<ServiceDefinition> filtered = new ArrayList<>();
        for (ServiceDefinition service : services) {
            if (service.getType().equalsIgnoreCase(type)) {
                filtered.add(service);
            }
        }
        return filtered;
    }
    
    /**
     * Filters services by algorithm.
     * 
     * @param services the list of services to filter
     * @param algorithm the algorithm to filter by
     * @return a list of services matching the specified algorithm
     */
    public static List<ServiceDefinition> filterByAlgorithm(List<ServiceDefinition> services, String algorithm) {
        List<ServiceDefinition> filtered = new ArrayList<>();
        for (ServiceDefinition service : services) {
            if (service.getAlgorithm().equalsIgnoreCase(algorithm)) {
                filtered.add(service);
            }
        }
        return filtered;
    }
    
    /**
     * Gets all unique service types from the list.
     * 
     * @param services the list of services
     * @return a list of unique service types
     */
    public static List<String> getUniqueTypes(List<ServiceDefinition> services) {
        List<String> types = new ArrayList<>();
        for (ServiceDefinition service : services) {
            if (!types.contains(service.getType())) {
                types.add(service.getType());
            }
        }
        return types;
    }

    /**
     * Gets the name of the provider that was read in from the config file.
     * 
     * @return a String that contains the provider name
     */
    public String getName() {
        return name;
    }

    /**
     * Gets the descripton that was read in from the config file.
     * 
     * @return a String that contains the description
     */
    public String getDesc() {
        return description;
    }     
}
