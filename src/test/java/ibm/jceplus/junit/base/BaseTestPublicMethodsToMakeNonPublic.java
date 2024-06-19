/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.Security;
import java.util.Enumeration;
import java.util.Vector;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

abstract public class BaseTestPublicMethodsToMakeNonPublic extends BaseTest {
    private boolean debug = false;
    private boolean debugAllChecked = false;

    // --------------------------------------------------------------------------
    //
    //
    public BaseTestPublicMethodsToMakeNonPublic(String providerName) {
        super(providerName);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {}

    // --------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    // --------------------------------------------------------------------------
    // Implementing testcase must override this method to indicate whether
    // the given method is meant to be public and explitly called by users.  Any 
    // public methods of public provider classes not flagged as allowed will be 
    // reported as a test failure.
    //
    abstract public boolean isMethodMeantToBePublicAndExplicitlyCallableByUsers(Method method);

    // --------------------------------------------------------------------------
    //
    //
    public void testCheckForPublicMethods() throws Exception {
        Vector<String> publicMethodNamesToCheck = new Vector<String>();

        String[] classNames = getClassNamesInSamePackage(
                Security.getProvider(providerName).getClass().getName());
        for (int index = 0; index < classNames.length; ++index) {
            Method[] publicMethods = getPublicMethodsOfClass(classNames[index]);

            for (int methodIndex = 0; methodIndex < publicMethods.length; ++methodIndex) {
                Method publicMethod = publicMethods[methodIndex];
                if (isMethodMeantToBePublicAndExplicitlyCallableByUsers(publicMethod) == false) {
                    String methodSignature = getPrintFriendlyMethodSignature(publicMethod);
                    publicMethodNamesToCheck.add(methodSignature);
                }
            }
        }

        String publicMethodNamesString = null;

        if (publicMethodNamesToCheck.size() > 0) {
            boolean printCondensed = false;
            if (printCondensed) {
                publicMethodNamesString = publicMethodNamesToCheck.toString();
            } else {
                StringBuffer sb = new StringBuffer();
                String[] methodNames = publicMethodNamesToCheck.toArray(new String[0]);
                for (int methodIndex = 0; methodIndex < methodNames.length; ++methodIndex) {
                    sb.append("\n");
                    sb.append(methodNames[methodIndex]);
                }
                publicMethodNamesString = sb.toString();
            }
        }

        assertTrue("Public methods to make non-public: " + publicMethodNamesString,
                (publicMethodNamesToCheck.size() == 0));
    }

    // --------------------------------------------------------------------------
    //
    //
    private String[] getClassNamesInSamePackage(String className) {
        Vector<String> v = new Vector<String>();

        try {
            String packageName = Class.forName(className).getPackage().getName();

            JarFile jarFile = getJarContainingClass(className);
            if (jarFile != null) {
                String[] jarClassNames = getClassNamesInJarFile(jarFile);
                for (int index = 0; index < jarClassNames.length; ++index) {
                    String jarClassName = jarClassNames[index];
                    try {
                        if (Class.forName(jarClassName).getPackage().getName()
                                .equals(packageName)) {
                            v.add(jarClassName);
                        }
                    } catch (Exception e) {
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }

        return v.toArray(new String[0]);
    }

    // --------------------------------------------------------------------------
    //
    //
    private JarFile getJarContainingClass(String className) {
        try {
            Class<?> c = Class.forName(className);
            ClassLoader cl = c.getClassLoader();
            URL url = cl.getResource(className.replace(".", "/") + ".class");

            int indexOfBang = url.toString().lastIndexOf(".jar!/");
            if (indexOfBang > 0) {
                URI jarURI = new URI(url.toString().substring(0, indexOfBang + 6));
                URL jarURL = jarURI.toURL();
                JarFile jarFile = ((JarURLConnection) jarURL.openConnection()).getJarFile();
                return jarFile;
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }

        return null;
    }

    // --------------------------------------------------------------------------
    //
    //
    private String[] getClassNamesInJarFile(JarFile jarFile) {
        Vector<String> v = new Vector<String>();

        try {
            Enumeration<JarEntry> jarEntries = jarFile.entries();
            while (jarEntries.hasMoreElements()) {
                JarEntry jarEntry = jarEntries.nextElement();
                String jarEntryName = jarEntry.getName();
                if (jarEntryName.endsWith(".class")) {
                    String className = jarEntryName.substring(0, jarEntryName.length() - 6)
                            .replace("/", ".");
                    v.add(className);
                }
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }

        return v.toArray(new String[0]);
    }

    // --------------------------------------------------------------------------
    // Returns the public methods of class if the class is public.  These methods
    // would be visible and accessible to users.
    //
    private Method[] getPublicMethodsOfClass(String className) {
        Vector<Method> v = new Vector<Method>();

        // System.out.println("Checking class " + className);

        try {
            Class<?> c = Class.forName(className);
            if (Modifier.isPublic(c.getModifiers())) {
                Method[] methods = c.getDeclaredMethods();
                for (int index = 0; index < methods.length; ++index) {
                    Method method = methods[index];
                    if (Modifier.isPublic(method.getModifiers())) {
                        String methodSignature = getPrintFriendlyMethodSignature(method);

                        if (debug || debugAllChecked) {
                            System.out.println("Checking public method " + methodSignature);
                        }

                        // Check if the method is declared by a superclass
                        //
                        Method superMethod = findMethod(c.getSuperclass(), method);
                        if (superMethod != null) {
                            // Check whether the method was declared public or
                            // not
                            //
                            if (Modifier.isPublic(superMethod.getModifiers())) {
                                if (debug || debugAllChecked) {
                                    System.out.println("  Ignoring, declared public by class "
                                            + superMethod.getDeclaringClass().getName());
                                }
                                continue;
                            } else {
                                if (debug) {
                                    System.out.println("  Declared non-public by class "
                                            + superMethod.getDeclaringClass().getName());
                                }
                            }
                        } else {
                            // Check if method declared by an interface
                            //
                            Class<?>[] interfaces = c.getInterfaces();
                            if (interfaces != null) {
                                boolean implementsInterfaceMethod = false;
                                boolean implementsPublicMethod = false;
                                for (int interfaceIndex = 0; interfaceIndex < interfaces.length; ++interfaceIndex) {

                                    Method interfaceMethod = findMethod(interfaces[interfaceIndex],
                                            method);
                                    if (interfaceMethod != null) {
                                        implementsInterfaceMethod = true;

                                        // Method is declared in a super-class,
                                        // check if it is declared public
                                        //
                                        if (Modifier.isPublic(interfaceMethod.getModifiers())) {
                                            if (debug || debugAllChecked) {
                                                System.out.println(
                                                        "  Ignoring, declared public by interface "
                                                                + interfaceMethod
                                                                        .getDeclaringClass()
                                                                        .getName());
                                            }
                                            implementsPublicMethod = true;
                                        } else {
                                            if (debug) {
                                                System.out.println(
                                                        "  Declared non-public by interface "
                                                                + interfaceMethod
                                                                        .getDeclaringClass()
                                                                        .getName());
                                            }
                                        }

                                        break;
                                    }
                                }

                                if (implementsPublicMethod) {
                                    continue;
                                }

                                if ((implementsInterfaceMethod == false)
                                        && (debug || debugAllChecked)) {
                                    System.out.println(
                                            "  Method is declared in class and does not override or provide implementation");
                                }
                            }
                        }

                        if (debug || debugAllChecked) {
                            System.out.println("  Adding method to list");
                        }

                        v.add(method);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }

        return v.toArray(new Method[0]);
    }

    // --------------------------------------------------------------------------
    //
    //
    private Method findMethod(Class<?> c, Method method) {
        if (c == null) {
            return null;
        }

        // Check the methods of this class
        Method[] checkMethods = c.getMethods();
        for (int methodIndex = 0; methodIndex < checkMethods.length; ++methodIndex) {
            Method checkMethod = checkMethods[methodIndex];
            if (checkMethod.getName().equals(method.getName())) {
                // Check the parameters
                //
                Class<?>[] methodParms = method.getParameterTypes();
                Class<?>[] checkMethodParms = checkMethod.getParameterTypes();
                boolean parmsMatch = true;
                if (methodParms.length == checkMethodParms.length) {
                    for (int parmIndex = 0; parmIndex < methodParms.length; ++parmIndex) {
                        if (methodParms[parmIndex].equals(checkMethodParms[parmIndex]) == false) {
                            parmsMatch = false;
                            break;
                        }
                    }
                }

                if (parmsMatch) {
                    return checkMethod;
                }
            }
        }

        return null;
    }

    // --------------------------------------------------------------------------
    //
    //
    protected String getPrintFriendlyMethodSignature(Method method) {
        StringBuffer sb = new StringBuffer();
        sb.append(method.getDeclaringClass().getName() + "." + method.getName());
        sb.append("(");

        Type[] parameterTypes = method.getGenericParameterTypes();
        for (int parmIndex = 0; parmIndex < parameterTypes.length; ++parmIndex) {
            if (parmIndex > 0) {
                sb.append(",");
            }
            sb.append(parameterTypes[parmIndex].toString());
        }

        sb.append(")");
        return sb.toString();
    }

}
