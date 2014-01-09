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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.util.Hashtable;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.everit.osgi.service.javasecurity.JavaSecurityFactory;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

/**
 * Registers a {@link JavaSecurityFactory} for Bouncy Castle security provider.
 */
public class Activator implements BundleActivator {

    /**
     * The Bouncy Castle specific {@link JavaSecurityFactory}.
     */
    private static class BouncyCastleFactory implements JavaSecurityFactory {

        @Override
        public KeyStore createKeyStore(final String type, final Provider provider) {
            try {
                return KeyStore.getInstance(type, provider);
            } catch (KeyStoreException e) {
                throw new IllegalStateException("failed to create keystore with type [" + type + "] and provider ["
                        + provider.getName() + "]", e);
            }
        }

        @Override
        public Provider createProvider() {
            return new BouncyCastleProvider();
        }

    }

    /**
     * The {@link ServiceRegistration} created by the activator.
     */
    private ServiceRegistration<JavaSecurityFactory> javaSecurityFactorySR;

    @Override
    public void start(final BundleContext context) throws Exception {
        JavaSecurityFactory javaSecurityFactory = new BouncyCastleFactory();
        Hashtable<String, Object> props = new Hashtable<String, Object>();
        Provider provider = javaSecurityFactory.createProvider();
        props.put(JavaSecurityFactory.PROVIDER_CLASS, provider.getClass().getName());
        props.put(JavaSecurityFactory.PROVIDER_NAME, provider.getName());
        props.put(JavaSecurityFactory.PROVIDER_VERSION, Double.valueOf(provider.getVersion()));
        javaSecurityFactorySR = context.registerService(JavaSecurityFactory.class, javaSecurityFactory, props);
    }

    @Override
    public void stop(final BundleContext context) throws Exception {
        if (javaSecurityFactorySR != null) {
            javaSecurityFactorySR.unregister();
            javaSecurityFactorySR = null;
        }
    }

}
