/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
