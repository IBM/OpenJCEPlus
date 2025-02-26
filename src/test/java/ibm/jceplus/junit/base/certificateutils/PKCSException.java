/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base.certificateutils;

import java.security.GeneralSecurityException;

/**
 * PKCSException is a wrapper exception for exceptions thrown by the JCE.
 * If the PKCSException stems from another exception, the exception
 * that the PKCSException wraps will be accessible with the getRelatedException
 * method.
 */

public final class PKCSException extends GeneralSecurityException {

    static final long serialVersionUID = 7056416762508378700L;

    private Exception e; // Stores the original exception

    //
    // Constructors
    //

    /**
     * Constructs a PKCSException with no detail
     * message.  A detail message is a String that describes this
     * particular exception.
     */
    public PKCSException() {
        super();
        this.e = null;
    }

    /**
     * Constructs a PKCSException with the specified
     * detail message. A detail message is a String that describes
     * this particular exception, which may, for example, specify
     * the invalid argument.
     *
     * @param msg the detail message.
     */
    public PKCSException(String msg) {
        super(msg);
        this.e = null;
    }

    /**
     * Constructs a PKCSException with the specified
     * detail message and stores the specified exception.
     * A detail message is a String that describes
     * this particular exception, which may, for example, specify
     * the invalid argument.
     *
     * @param msg the detail message.
     * @param e Exception from which the PKCSException stems.
     */
    public PKCSException(Exception e, String msg) {
        super(msg);
        this.e = e;
    }

    //
    // Public methods
    //

    /**
     * Returns the exception from which the PKCSException stems.
     *
     * @return Exception from which the PKCSException stems
     * or null if the PKCSException is not related to another exception.
     */
    public Exception getRelatedException() {
        return this.e;
    }
}
