/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import com.ibm.crypto.plus.provider.openssl.OpenSSLException;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link OpenSSLException} constructors and code fields.
 * Exercises the exception class directly without requiring a native provider.
 */
@Tag(Tags.OPENJCEPLUS_OCK_NAME)
@Tag(Tags.OPENJCEPLUS_OPENSSL_NAME)
public class TestOpenSSLException {

    @Test
    public void testStringConstructorSetsUnspecifiedCode() {
        OpenSSLException ex = new OpenSSLException("test message");
        assertEquals("test message", ex.getMessage());
        assertEquals(OpenSSLException.OPENSSL_UNSPECIFIED, ex.getCode());
    }

    @Test
    public void testStringThrowableConstructorSetsUnspecifiedCode() {
        Throwable cause = new RuntimeException("cause");
        OpenSSLException ex = new OpenSSLException("wrapped", cause);
        assertEquals("wrapped", ex.getMessage());
        assertSame(cause, ex.getCause());
        assertEquals(OpenSSLException.OPENSSL_UNSPECIFIED, ex.getCode());
    }

    @Test
    public void testIntConstructorFormatsCodeAsHex() {
        OpenSSLException ex = new OpenSSLException(OpenSSLException.OPENSSL_UNSPECIFIED);
        assertNotNull(ex.getMessage());
        assertEquals("0x" + Integer.toHexString(OpenSSLException.OPENSSL_UNSPECIFIED),
                ex.getMessage());
        assertEquals(OpenSSLException.OPENSSL_UNSPECIFIED, ex.getCode());
    }

    @Test
    public void testUnspecifiedConstantValue() {
        assertEquals(0x80000000, OpenSSLException.OPENSSL_UNSPECIFIED);
    }

    @Test
    public void testIsCheckedException() {
        // OpenSSLException extends NativeException, a checked exception
        assertTrue(Exception.class.isAssignableFrom(OpenSSLException.class));
        assertFalse(RuntimeException.class.isAssignableFrom(OpenSSLException.class));
    }
}
