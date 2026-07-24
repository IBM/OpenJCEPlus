/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests.parameters.resolvers;

import java.util.List;

public class RSAMultithreadKeySizeListParameterResolver extends KeySizeListParameterResolver {

    public RSAMultithreadKeySizeListParameterResolver() {
        super(List.of(2048));
    }
}
