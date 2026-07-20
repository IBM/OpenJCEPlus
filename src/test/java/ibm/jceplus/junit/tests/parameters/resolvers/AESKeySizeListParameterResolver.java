/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests.parameters.resolvers;

import java.util.List;

public class AESKeySizeListParameterResolver extends KeySizeListParameterResolver {

    public AESKeySizeListParameterResolver() {
        super(List.of(128, 192, 256));
    }
}
