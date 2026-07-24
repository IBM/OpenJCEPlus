/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests.parameters.resolvers;

import java.util.List;

public class RSAKeySizeListParameterResolver extends KeySizeListParameterResolver {

    public RSAKeySizeListParameterResolver() {
        super(List.of(512, 1024, 2048, 3072, 4096));
    }
}
