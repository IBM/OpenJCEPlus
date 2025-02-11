/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.certificateutils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import jdk.internal.logger.SimpleConsoleLogger;
import sun.util.logging.PlatformLogger;

/**
 * A utility class for debuging.
 *
 */
public class Debug {

    private String prefix;
    private static String args;
    private static SimpleConsoleLogger tl = null;

    static {
        args = System.getProperty("java.security.debug");
        String args2 = System.getProperty("java.security.auth.debug");
        if (args == null) {
            args = args2;
        } else {
            args = args + "," + args2;
        }

        if (args != null) {
            args = marshal(args);
            if (args.equals("help")) {
                Help();
            }
        }

        if (args != null) {
            //The debug flag may look like java.security.debug = 
            String[] tokens = args.split(",");
            for (int i = 0, len = tokens.length; i < len; ++i) {
                if ("ibmpkcs".equalsIgnoreCase(tokens[i].trim())) {
                    System.out.println("IBMPKCS Build-Level: -"
                            + getDebugDate("com.ibm.security.pkcs1.PKCS1"));
                    break;
                }
            }
        }
    }

    public static final long TYPE_NONE = 0x00000;

    /**
     * Defines a mask containing all of the possible types.
     */

    public static final long TYPE_ALL = 0xFFFFFFFFFFFFFFFFL;

    /**
     * Defines an informational message.
     * Use this type to indicate conditions that are worth noting but that 
     * do not require a user to take any precautions or perform an action. 
     * Sparing use of this type is suggested.
     * An informational message is less severe than a warning message.
     * This value is the same as {@link #TYPE_INFORMATION TYPE_INFORMATION}.
     */

    public static final long TYPE_INFO = 0x00001;

    /**
     * Defines an informational message.
     * This value is the same as {@link #TYPE_INFO TYPE_INFO}.
     */

    public static final long TYPE_INFORMATION = TYPE_INFO;

    /**
     * Defines a warning message.
     * Use this type to inform a user that an abnormal condition has been 
     * detected.  The particular condition will dictate whether the user has
     * to take any action.
     * A warning message is less severe than an error message.
     * This value is the same as {@link #TYPE_WARNING TYPE_WARNING}.
     */

    public static final long TYPE_WARN = 0x00002;

    /**
     * Defines a warning message.
     * This value is the same as {@link #TYPE_WARN TYPE_WARN}.
     */

    public static final long TYPE_WARNING = TYPE_WARN;

    /**
     * Defines an error message.
     * Use this type to inform the user of a serious failure in the execution
     * of a program.
     * An error message is less severe than a fatal message.
     * This value is the same as {@link #TYPE_ERROR TYPE_ERROR}.
     * <p>
     * Note:  <code>TYPE_ERR</code> is included in the default mask of a 
     * Logger and should not be confused with 
     * <code>TYPE_ERROR_EXC</code>, which is intended to be used for
     * trace records by Trace.
     */

    public static final long TYPE_ERR = 0x00004;

    /**
     * Defines an error message.
     * This value is the same as {@link #TYPE_ERR TYPE_ERR}.
     * <p>
     * Note:  <code>TYPE_ERR</code> is included in the default mask of a 
     * Logger and should not be confused with 
     * <code>TYPE_ERROR_EXC</code>, which is intended to be used for
     * trace records by Trace.
     */

    public static final long TYPE_ERROR = TYPE_ERR;

    /**
     * Defines a fatal message.
     * Use this type to report an error from which the program cannot
     * recover.
     * A fatal message is the most severe message.
     */

    public static final long TYPE_FATAL = 0x00008;

    /**
     * Defines the default message types.  The value is
     * <code>(TYPE_INFO | TYPE_WARN | TYPE_ERR | TYPE_FATAL</code>.
     */

    public static final long TYPE_DEFAULT_MESSAGE = TYPE_INFO | TYPE_WARN | TYPE_ERR | TYPE_FATAL;

    /**
     * Defines an application programming interface (API) 
     * trace point.
     */

    public static final long TYPE_API = 0x000010;

    /**
     * Defines a callback method trace point.  Callbacks are
     * typically used in listener classes, which have registered
     * with another object to be notified when a specific record
     * occurs.
     */

    public static final long TYPE_CALLBACK = 0x000020;

    /**
     * Defines method entry and exit trace points.
     *
     * @deprecated
     *   <code>TYPE_ENTRY_EXIT</code> has been split into
     *   <code>TYPE_ENTRY</code> and <code>TYPE_EXIT</code>.
     */
    @Deprecated
    public static final long TYPE_ENTRY_EXIT = 0x000040;

    /**
     * Defines method entry trace points.  
     * An entry trace point should be added to every 
     * significant method to track movement through an
     * application.  Trivial methods, such as getters and
     * setters, generally don't have entry or exit trace points
     * because of the added overhead.
     */

    public static final long TYPE_ENTRY = 0x000080;

    /**
     * Defines method exit trace points.
     * An exit trace point should be added to every 
     * significant method to track movement through an
     * application.  Trivial methods, such as getters and
     * setters, generally don't have entry or exit trace points
     * because of the added overhead.
     */

    public static final long TYPE_EXIT = 0x000100;

    /**
     * Defines an error or exception condition trace point.
     * This type can be used to trace any exceptional 
     * condition.
     * <p>
     * Note:  <code>TYPE_ERROR_EXC</code> is included in the default mask of a 
     * Trace and should not be confused with 
     * <code>TYPE_ERROR</code>, which is intended to be used for
     * message records by Logger.
     */

    public static final long TYPE_ERROR_EXC = 0x000200;

    /**
     * Defines a miscellaneous data trace point.
     * This type can be used to trace information not
     * covered by any other trace type.
     */

    public static final long TYPE_MISC_DATA = 0x000400;

    /**
     * Defines an object creation (constructor) trace point.
     */

    public static final long TYPE_OBJ_CREATE = 0x000800;

    /**
     * Defines an object deletion (destructor) trace point.
     * This type would generally be used in a <code>finalize</code>
     * method.
     */

    public static final long TYPE_OBJ_DELETE = 0x001000;

    /**
     * Defines a <code>private</code> method trace point.
     * Private trace points would be defined in methods with
     * private scope.
     */

    public static final long TYPE_PRIVATE = 0x002000;

    /**
     * Defines a public method trace point.  This typically
     * includes <code>package</code> and <code>protected</code>
     * scope, as all of these methods may be used by other 
     * classes.
     */

    public static final long TYPE_PUBLIC = 0x004000;

    /**
     * Defines a static method trace point.
     */

    public static final long TYPE_STATIC = 0x008000;

    /**
     * Defines a service code trace point.  Service code is
     * generally "low-level" code which provides commonly used services
     * to other classes.
     */

    public static final long TYPE_SVC = 0x010000;

    /**
     * Defines a performance-monitoring trace point.
     * This type can be used to measure the execution time of 
     * selected sections of an application.
     */

    public static final long TYPE_PERF = 0x020000;

    /**
     * Defines a "low-detail" trace point.  Some trace implementations 
     * prefer the notion of a "trace level," in which level 1 implies
     * minimal detail, level 2 implies more detail and level 3 implies
     * the most detail.  In such a system, these three types would be
     * used exclusively.
     */

    public static final long TYPE_LEVEL1 = 0x040000;

    /**
     * Defines a "medium-detail" trace point.  Some trace implementations 
     * prefer the notion of a "trace level," in which level 1 implies
     * minimal detail, level 2 implies more detail and level 3 implies
     * the most detail.  In such a system, these three types would be
     * used exclusively.
     */

    public static final long TYPE_LEVEL2 = 0x080000;

    /**
     * Defines a "high-detail" trace point.  Some trace implementations 
     * prefer the notion of a "trace level," in which level 1 implies
     * minimal detail, level 2 implies more detail and level 3 implies
     * the most detail.  In such a system, these three types would be
     * used exclusively.
     */

    public static final long TYPE_LEVEL3 = 0x100000;

    public Debug(String name, String rbName) {
        if (tl == null) {

            tl = SimpleConsoleLogger.makeSimpleLogger(name);
            tl.setPlatformLevel(PlatformLogger.Level.ALL);
        }
    }

    public static void Help() {
        System.err.println();
        System.err.println("all       turn on all debugging");
        System.err.println("access    print all checkPermission results");
        System.err.println("jar       jar verification");
        System.err.println("policy    loading and granting");
        System.err.println("scl       permissions SecureClassLoader assigns");
        System.err.println();
        System.err.println("The following can be used with access:");
        System.err.println();
        System.err.println("stack     include stack trace");
        System.err.println("domain    dumps all domains in context");
        System.err.println("failure   before throwing exception, dump stack");
        System.err.println("          and domain that didn't have permission");
        System.err.println();
        System.exit(0);
    }

    /**
     * Get a Debug object corresponding to whether or not the given
     * option is set. Set the prefix to be the same as option.
     */

    public static Debug getInstance(String option) {
        return getInstance(option, option);
    }

    /**
     * Get a Debug object corresponding to whether or not the given
     * option is set. Set the prefix to be prefix.
     */
    public static Debug getInstance(String option, String prefix) {
        if (isOn(option)) {
            return new Debug("com.ibm.misc.Debug", null);
        } else {
            return null;
        }
    }

    /**
     * True if the system property "security.debug" contains the
     * string "option".
     */
    public static boolean isOn(String option) {
        if (args == null)
            return false;
        else {
            if (args.indexOf("all") != -1)
                return true;
            else
                return (args.indexOf(option) != -1);
        }
    }

    private String getParms(Object[] parms) {
        String result = " ";
        for (int i = 0; i < parms.length; i++) {
            result = result + parms[i].toString() + " ";
        }
        return result;
    }

    public void data(long type, Object loggingClass, String loggingMethod, byte[] data) {
        Object[] parms = {data};
        tl.log(PlatformLogger.Level.FINER, (String) loggingClass + " " + loggingMethod, parms);
    }

    public void entry(long type, Object loggingClass, String loggingMethod) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "ENTRY");
    }

    public void entry(long type, Object loggingClass, String loggingMethod, Object parm1) {
        //Object[] parms = {parm1};
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "ENTRY");
    }

    public void entry(long type, Object loggingClass, String loggingMethod, Object parm1,
            Object parm2) {
        Object[] parms = {parm1, parm2};
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "ENTRY {0} {1}",
                parms);
    }

    public void entry(long type, Object loggingClass, String loggingMethod, Object[] parms) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "ENTRY {0}",
                parms);
    }

    public void exception(long type, Object loggingClass, String loggingMethod,
            Throwable throwable) {
        tl.log(PlatformLogger.Level.FINER, (String) loggingClass + " " + loggingMethod, throwable);
    }

    public void exit(long type, Object loggingClass, String loggingMethod) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN");
    }

    public void exit(long type, Object loggingClass, String loggingMethod, byte retValue) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN {0}",
                new Byte(retValue));
    }

    public void exit(long type, Object loggingClass, String loggingMethod, short retValue) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN {0}",
                new Short(retValue));
    }

    public void exit(long type, Object loggingClass, String loggingMethod, int retValue) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN {0}",
                new Integer(retValue));
    }

    public void exit(long type, Object loggingClass, String loggingMethod, long retValue) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN {0}",
                new Long(retValue));
    }

    public void exit(long type, Object loggingClass, String loggingMethod, float retValue) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN {0}",
                new Float(retValue));
    }

    public void exit(long type, Object loggingClass, String loggingMethod, double retValue) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN {0}",
                new Double(retValue));
    }

    public void exit(long type, Object loggingClass, String loggingMethod, char retValue) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN {0}",
                new Character(retValue));
    }

    public void exit(long type, Object loggingClass, String loggingMethod, boolean retValue) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN {0}",
                new Boolean(retValue));
    }

    public void exit(long type, Object loggingClass, String loggingMethod, Object retValue) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, "RETURN {0}",
                retValue);
    }

    public void stackTrace(long type, Object loggingClass, String loggingMethod) {
        StringWriter sw = new StringWriter();
        new Throwable().printStackTrace(new PrintWriter(sw));
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, sw.toString());
    }

    public void stackTrace(long type, Object loggingClass, String loggingMethod, String text) {
        StringWriter sw = new StringWriter();
        new Throwable(text).printStackTrace(new PrintWriter(sw));
        Object[] parms = {sw.toString()};
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, text, parms);
    }

    public void text(long type, Object loggingClass, String loggingMethod, String text) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, text);
    }

    public void text(long type, Object loggingClass, String loggingMethod, String text,
            Object parm1) {
        Object[] parms = {parm1};
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, text, parms);
    }

    public void text(long type, Object loggingClass, String loggingMethod, String text,
            Object parm1, Object parm2) {
        Object[] parms = {parm1, parm2};
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, text, parms);
    }

    public void text(long type, Object loggingClass, String loggingMethod, String text,
            Object[] parms) {
        tl.logp(PlatformLogger.Level.FINER, (String) loggingClass, loggingMethod, text, parms);
    }

    /**
     * return a hexadecimal printed representation of the specified
     * BigInteger object. the value is formatted to fit on lines of
     * at least 75 characters, with embedded newlines. Words are
     * separated for readability, with eight words (32 bytes) per line.
     */
    public static String toHexString(BigInteger b) {
        String hexValue = b.toString(16);
        StringBuffer buf = new StringBuffer(hexValue.length() * 2);

        if (hexValue.startsWith("-")) {
            buf.append("   -");
            hexValue = hexValue.substring(1);
        } else {
            buf.append("    "); // four spaces
        }
        if ((hexValue.length() % 2) != 0) {
            // add back the leading 0
            hexValue = "0" + hexValue;
        }
        int i = 0;
        while (i < hexValue.length()) {
            // one byte at a time
            buf.append(hexValue.substring(i, i + 2));
            i += 2;
            if (i != hexValue.length()) {
                if ((i % 64) == 0) {
                    buf.append("\n    "); // line after eight words
                } else if (i % 8 == 0) {
                    buf.append(" "); // space between words
                }
            }
        }
        return buf.toString();
    }

    /**
     * change a string into lower case except permission classes and URLs.
     */
    private static String marshal(String args) {
        if (args != null) {
            StringBuffer target = new StringBuffer();
            StringBuffer source = new StringBuffer(args);

            // obtain the "permission=<classname>" options
            // the syntax of classname: IDENTIFIER.IDENTIFIER
            // the regular express to match a class name:
            // "[a-zA-Z_$][a-zA-Z0-9_$]*([.][a-zA-Z_$][a-zA-Z0-9_$]*)*"
            String keyReg = "[Pp][Ee][Rr][Mm][Ii][Ss][Ss][Ii][Oo][Nn]=";
            String keyStr = "permission=";
            String reg = keyReg + "[a-zA-Z_$][a-zA-Z0-9_$]*([.][a-zA-Z_$][a-zA-Z0-9_$]*)*";
            Pattern pattern = Pattern.compile(reg);
            Matcher matcher = pattern.matcher(source);
            StringBuffer left = new StringBuffer();
            while (matcher.find()) {
                String matched = matcher.group();
                target.append(matched.replaceFirst(keyReg, keyStr));
                target.append("  ");

                // delete the matched sequence
                matcher.appendReplacement(left, "");
            }
            matcher.appendTail(left);
            source = left;

            // obtain the "codebase=<URL>" options
            // the syntax of URL is too flexible, and here assumes that the
            // URL contains no space, comma(','), and semicolon(';'). That
            // also means those characters also could be used as separator
            // after codebase option.
            // However, the assumption is incorrect in some special situation
            // when the URL contains comma or semicolon
            keyReg = "[Cc][Oo][Dd][Ee][Bb][Aa][Ss][Ee]=";
            keyStr = "codebase=";
            reg = keyReg + "[^, ;]*";
            pattern = Pattern.compile(reg);
            matcher = pattern.matcher(source);
            left = new StringBuffer();
            while (matcher.find()) {
                String matched = matcher.group();
                target.append(matched.replaceFirst(keyReg, keyStr));
                target.append("  ");

                // delete the matched sequence
                matcher.appendReplacement(left, "");
            }
            matcher.appendTail(left);
            source = left;

            // convert the rest to lower-case characters
            target.append(source.toString().toLowerCase(Locale.ENGLISH));

            return target.toString();
        }

        return null;
    }

    private final static char[] hexDigits = "0123456789abcdef".toCharArray();

    public static String toString(byte[] b) {
        if (b == null) {
            return "(null)";
        }
        StringBuilder sb = new StringBuilder(b.length * 3);
        for (int i = 0; i < b.length; i++) {
            int k = b[i] & 0xff;
            if (i != 0) {
                sb.append(':');
            }
            sb.append(hexDigits[k >>> 4]);
            sb.append(hexDigits[k & 0xf]);
        }
        return sb.toString();
    }

    // Get the date from the ImplementationVersion in the manifest file
    private static String getDebugDate(String className) {
        String versionDate = "Unknown";
        try {
            Class<?> thisClass = Class.forName(className);
            Package thisPackage = thisClass.getPackage();
            String versionInfo = thisPackage.getImplementationVersion();
            int index = versionInfo.indexOf("_");
            versionDate = versionInfo.substring(index + 1);
        } catch (Exception e) {
            //IGNORE EXCEPTION
        }
        return versionDate;
    }
}
