/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests.parameters.resolvers;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;

public abstract class KeySizeListParameterResolver implements ParameterResolver {
    private List<Integer> keySizes;

    protected KeySizeListParameterResolver(List<Integer> keySizes) {
        this.keySizes = keySizes;
    }

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        Type type = parameterContext.getParameter().getParameterizedType();
        if (!(type instanceof ParameterizedType pt)) return false;
        return pt.getRawType() == List.class &&
                pt.getActualTypeArguments()[0] == Integer.class;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        return keySizes;
    }
}
