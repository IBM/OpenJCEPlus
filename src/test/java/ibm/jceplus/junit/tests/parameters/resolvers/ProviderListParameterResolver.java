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
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;

public class ProviderListParameterResolver implements ParameterResolver {

    @Override
    public boolean supportsParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        Type type = parameterContext.getParameter().getParameterizedType();
        if (!(type instanceof ParameterizedType pt)) return false;
        return pt.getRawType() == Set.class &&
                pt.getActualTypeArguments()[0] == String.class;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext, ExtensionContext extensionContext) {
        Set<String> providers = extensionContext.getTags().stream()
                                        .filter(pn -> !pn.equalsIgnoreCase("multithread"))
                                        .collect(Collectors.toSet());
        return providers;
    }
}
