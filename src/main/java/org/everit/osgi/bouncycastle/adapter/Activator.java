package org.everit.osgi.bouncycastle.adapter;

/*
 * Copyright (c) 2011, Everit Kft.
 *
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 */

import java.security.Provider;
import java.security.Security;
import java.util.Hashtable;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

/**
 * Registers a {@link Provider} OSGi service based on the Bouncy Castle security provider.
 */
public class Activator implements BundleActivator {

    /**
     * Service property name. The class of the created provide by the {@link #createProvider()} method.
     */
    private static final String PROVIDER_CLASS = "providerClass";

    /**
     * Service property name. The name of the created provide by the {@link #createProvider()} method. The service
     * property value must be the return value of {@link Provider#getName()}.
     */
    private static final String PROVIDER_NAME = "providerName";

    /**
     * Service property name. The version of the created provide by the {@link #createProvider()} method. The service
     * property value must be the return value of {@link Provider#getVersion()}.
     */
    private static final String PROVIDER_VERSION = "providerVersion";

    /**
     * The {@link ServiceRegistration} created by the activator.
     */
    private ServiceRegistration<Provider> providerSR;

    private String providerName;

    @Override
    public void start(final BundleContext context) throws Exception {
        Provider provider = new BouncyCastleProvider();
        Hashtable<String, Object> props = new Hashtable<String, Object>();
        props.put(PROVIDER_CLASS, provider.getClass().getName());
        providerName = provider.getName();
        props.put(PROVIDER_NAME, providerName);
        props.put(PROVIDER_VERSION, Double.valueOf(provider.getVersion()));
        providerSR = context.registerService(Provider.class, provider, props);
        Security.addProvider(provider);
    }

    @Override
    public void stop(final BundleContext context) throws Exception {
        if (providerSR != null) {
            providerSR.unregister();
            providerSR = null;
            Security.removeProvider(providerName);
        }
    }

}
