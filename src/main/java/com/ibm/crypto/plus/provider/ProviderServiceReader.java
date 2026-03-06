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
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

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
    private BufferedReader reader = null;
    private String defaults = null;
    private Set<String> setDefAttributes = null;
    private Properties defPr = null;
    private boolean def = false;
    
    /**
     * Represents a single service definition parsed from the file.
     */
    public static class ServiceDefinition {
        private final String type;
        private final String algorithm;
        private final String className;
        private final List<String> aliases;
        private final Map<String, String> attributes;
       
        public ServiceDefinition(String type, String algorithm, String className, 
                               List<String> aliases, Map<String, String> attributes) {
            this.type = type;
            this.algorithm = algorithm;
            this.className = className;
            this.aliases = aliases != null ? new ArrayList<>(aliases) : new ArrayList<>();
            this.attributes = attributes != null ? new HashMap<>(attributes) : new HashMap<>();
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
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("ServiceDefinition[")
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
        Set<String> setAliases = new HashSet<>();
        Set<String> setAttributes = new HashSet<>();
        Set<String> setServices = new HashSet<>();
        BufferedReader rd = null;
        Properties pr = new Properties();

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

            pr.load(rd);

            Set<String> keys = pr.stringPropertyNames();

            //Split keys in groups: Aliases, Attributes and Services
            for (String key : keys) {
                String[] parts = key.split("\\.");

                if (parts.length == 3 && parts[0].equalsIgnoreCase("Service")) {
                    setServices.add(key);
                } else if (parts.length == 4 && parts[2].equalsIgnoreCase("alias")) {
                    setAliases.add(key);
                } else if (parts.length == 5 && parts[2].equalsIgnoreCase("attr")) {
                    setAttributes.add(key);
                } else if (parts.length == 1 && parts[0].equalsIgnoreCase("name")) {
                    name = pr.getProperty(key);
                } else if (parts.length == 1 && parts[0].equalsIgnoreCase("description")) {
                    description = pr.getProperty(key);
                } else if (parts.length == 1 && parts[0].equalsIgnoreCase("default")) {
                    defaults = pr.getProperty(key);
                } else {
                    throw new IOException("Invalid key: " + key);
                }
            }
 
            //Get default values, if needed.
            if (defaults != null &&
                (defaults.equalsIgnoreCase("true" ) ||
                defaults.equals("1"))) {
                BufferedReader defRd = new BufferedReader(new StringReader(DefaultProviderAttrs.defaultProvAttrs));
                defPr = new Properties();
                defPr.load(defRd);

                //Add default Services
                Set<String> defKeys = defPr.stringPropertyNames();

                for (String key : defKeys) {
                    String[] parts = key.split("\\.");

                    if (parts.length == 3 && parts[0].equalsIgnoreCase("Service")) {
                        List<String> aliases = processAliases(parts, defPr, pr, setAliases);
                        Map<String, String> attributes = processAttributes(parts, setAttributes, defPr, pr);
                        ServiceDefinition service = new ServiceDefinition(parts[1], parts[2], defPr.getProperty(key), aliases, attributes);
                        if (service != null) {
                            services.add(service);
                            aliases = null;
                            attributes.clear();
                        }
                    }
                }
  
                def = true;
            }

            for (String key : setServices) {
                String[] parts = key.split("\\.");
                List<String> aliases = processAliases(parts, pr, null, null);
                Map<String, String> attributes = processAttributes(parts, setAttributes, pr, null);
                ServiceDefinition service = new ServiceDefinition(parts[1], parts[2], pr.getProperty(key), aliases, attributes);
                if (service != null) {
                    services.add(service);
                    aliases = null;
                    attributes.clear();
                }
            }
        } catch (Exception e) {
            throw new IOException("File issue: " + e.getMessage());
        }
       
        return services;
    }
       
    /**
     * Process the aliases array from a putService statement.
     * Assume that there is only ever one .add, .replace or .delete property.
     * per Type and Algorithm.
     *
     * @param parts the service key parts (Service, Type, Algorithm)
     * @param defaultPr the default properties (can be null)
     * @param configPr the config file properties (can be null)
     * @param configAliases the set of alias keys from config file (can be null)
     * @return a list of alias strings
     */
    private List<String> processAliases(String[] parts, Properties defaultPr, Properties configPr, Set<String> configAliases) {
        List<String> Aliases = new ArrayList<>();
        String keyBase = parts[1] + "." + parts[2] + ".alias";

        //There is only ever one .add, .replace or .delete per Type and Algorithm.
        //The defaults if applicable need to be added in first and then the
        //properties from the config are applied.
        //.add will add those alaises to the list with the default ones(if applicable)
        //.delete will remove the aliasses from the current list of aliases
        //.replace will remove the current list of aliases and then add the new ones.

        //add the default aliases if applicable.
        if (defaultPr != null) {
            String value = defaultPr.getProperty(keyBase + ".add");
            if (value != null) {
                String[] aliases = value.split("\\s*,\\s*");
                for (String alias : aliases) {
                    Aliases.add(alias);
                }
            }
        }

        //Process the aliases from the config file.
        if (configPr != null) {
            String value = configPr.getProperty(keyBase + ".add");
            if (value != null) {
                String[] aliases = value.split("\\s*,\\s*");
                for (String alias : aliases) {
                    Aliases.add(alias);
                }
            }

            value = configPr.getProperty(keyBase + ".delete");
            if (value != null) {
                String[] aliases = value.split("\\s*,\\s*");
                for (String alias : aliases) {
                    Aliases.remove(alias);
                }
            }
        
            value = configPr.getProperty(keyBase + ".replace");
            if (value != null) {
                String[] aliases = value.split("\\s*,\\s*");
                Aliases.clear();
                for (String alias : aliases) {
                    Aliases.add(alias);
                }
            }
        }

        return Aliases;
    }
    
    /**
     * Parses attributes from a putService statement.
     *
     * @param parts the service key parts (Service, Type, Algorithm)
     * @param configAttrs the set of attribute keys from config file
     * @param defaultPr the default properties (can be null)
     * @param configPr the config file properties (can be null)
     * @return a map of attribute key-value pairs
     */
    private Map<String, String> processAttributes(String[] parts, Set<String> configAttrs, Properties defaultPr, Properties configPr) {
        Map<String, String> attributes = new HashMap<>();
        String search = parts[1] + "." + parts[2] + ".attr";

        //Only .add, and .delete are supported for Attributes
        //The defaults if applicable need to be added those in first and then the
        //properties from the config are applied.
        //.add will add the Attributes to the list with the default ones(if applicable)
        //.delete will remove the Attribute from the current list of Attributes

        //add the default Attributes if applicable.
        if (defaultPr != null) {
            //Create the list of default Attributes
            if (setDefAttributes == null) {
                setDefAttributes = new HashSet<>();

                Set<String> keys = defaultPr.stringPropertyNames();

                //Split keys in groups: Aliases, Attributes and Services
                for (String key : keys) {
                    String[] defParts = key.split("\\.");

                    if (defParts.length == 5 && defParts[2].equalsIgnoreCase("attr")) {
                        setDefAttributes.add(key);
                    }
                }
            }

            // Add Default Attributes
            if (setDefAttributes != null && setDefAttributes.size() > 0) {
                for (String attribute : setDefAttributes) {
                    if (attribute.startsWith(search)) {
                        String[] pieces = attribute.split("\\.");
                        if (pieces[3].equalsIgnoreCase("add")) {
                            attributes.put(pieces[4], defaultPr.getProperty(attribute));
                        }
                    }
                }
            }
        }

        //Add or remove Attributes based on config file.
        //Process adds first, then deletes to ensure correct order
        if (configPr != null && configAttrs != null) {
            // First pass: process all "add" operations
            for (String attribute : configAttrs) {
                if (attribute.startsWith(search)) {
                    String[] pieces = attribute.split("\\.");
                    if (pieces[3].equalsIgnoreCase("add")) {
                        attributes.put(pieces[4], configPr.getProperty(attribute));
                    }
                }
            }
            // Second pass: process all "delete" operations
            for (String attribute : configAttrs) {
                if (attribute.startsWith(search)) {
                    String[] pieces = attribute.split("\\.");
                    if (pieces[3].equalsIgnoreCase("delete")) {
                        attributes.remove(pieces[4]);
                    }
                }
            }
        }
        return attributes;
    }
    
    /**
     * Filters services by type.
     * 
     * @param services the list of services to filter
     * @param type the service type to filter by
     * @return a list of services matching the specified type
     */
    public List<ServiceDefinition> filterByType(List<ServiceDefinition> services, String type) {
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
    public List<ServiceDefinition> filterByAlgorithm(List<ServiceDefinition> services, String algorithm) {
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
    public List<String> getUniqueTypes(List<ServiceDefinition> services) {
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
