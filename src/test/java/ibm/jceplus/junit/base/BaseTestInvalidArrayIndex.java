/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestInvalidArrayIndex extends BaseTestJunit5 {

    private static final byte[] BYTES = new byte[20];

    static int IAE = 1; // IllegalArgumentException
    static int AIOOBE = 2; // ArrayIndexOutOfBoundsException

    @Test
    public void testInvalidArrayIndex() throws Exception {
        // test various spec classes with invalid array offset, length values
        // and see if the expected exception is thrown
        try {
            dotest(IAE, GCMParameterSpec.class, 12, BYTES, -1, BYTES.length);
            dotest(IAE, GCMParameterSpec.class, 12, BYTES, 0, -2);
            dotest(IAE, GCMParameterSpec.class, 12, BYTES, -Integer.MAX_VALUE + BYTES.length + 2,
                    Integer.MAX_VALUE - 1);

            dotest(AIOOBE, IvParameterSpec.class, BYTES, -4, BYTES.length);
            dotest(AIOOBE, IvParameterSpec.class, BYTES, 0, -5);
            dotest(AIOOBE, IvParameterSpec.class, BYTES, -Integer.MAX_VALUE + BYTES.length,
                    Integer.MAX_VALUE);

            dotest(AIOOBE, RC2ParameterSpec.class, 0, BYTES, -5);
            dotest(IAE, RC2ParameterSpec.class, 0, BYTES, BYTES.length - 1);

            dotest(IAE, RC5ParameterSpec.class, 0, 0, Integer.MAX_VALUE, BYTES, 0);
            dotest(AIOOBE, RC5ParameterSpec.class, 0, 0, 32, BYTES, -3);
            dotest(AIOOBE, RC5ParameterSpec.class, 0, 0, Integer.MAX_VALUE, BYTES,
                    BYTES.length - Integer.MAX_VALUE);
            dotest(IAE, RC5ParameterSpec.class, 0, 0, 16, BYTES, Integer.MAX_VALUE - 2);

            dotest(IAE, SecretKeySpec.class, BYTES, 1, BYTES.length, "");
            dotest(IAE, SecretKeySpec.class, BYTES, 0, Integer.MAX_VALUE - 3, "");
            dotest(AIOOBE, SecretKeySpec.class, BYTES, -Integer.MAX_VALUE + BYTES.length + 2,
                    Integer.MAX_VALUE - 1, "");
            System.out
                    .println("Test Passed for IVParameterSpec, GCMParameterSpec and SecretKeySpec");
            assertTrue(true, "Spec Tests passed for IVParamerSpec, GCMParameterSpec and SecretKeySpec");
        } catch (Exception ex) {
            assertTrue(false, "Spec Tests failed for IVParamerSpec, GCMParameterSpec and SecretKeySpec "
                    + ex.getMessage());
        }
    }

    private static void dotest(int expectedEx, Class<?> specCls, Object... args)
            throws NoSuchMethodException, InstantiationException, IllegalAccessException,
            IllegalArgumentException, InvocationTargetException {
        System.out.println("Testing " + specCls);
        String exName = (expectedEx == 1) ? "IAE" : "AIOOBE";
        Class<?>[] argsClz = new Class<?>[args.length];
        for (int i = 0; i < argsClz.length; i++) {
            argsClz[i] = (args[i] instanceof Integer ? Integer.TYPE : args[i].getClass());
        }
        Constructor<?> ctr = specCls.getConstructor(argsClz);
        try {
            ctr.newInstance(args);
            throw new RuntimeException("Should throw " + exName);
        } catch (InvocationTargetException ite) {
            Throwable cause = ite.getCause();
            if ((expectedEx == IAE && cause instanceof IllegalArgumentException)
                    || (expectedEx == AIOOBE && cause instanceof ArrayIndexOutOfBoundsException)) {
                System.out.println("Expected " + exName + " thrown => " + cause.getMessage());
            } else {
                throw new RuntimeException("Expected " + exName + " but got " + cause);
            }
        }
    }
}
