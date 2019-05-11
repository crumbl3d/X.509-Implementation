package implementation;

import code.*;
import gui.GuiInterfaceV1;
import x509.v3.*;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

public class MyCode extends CodeV3 {

    private KeyStore localKeyStore;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
        CertificateHelper.addBouncyCastleProvider();
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
            localKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (FileInputStream input = new FileInputStream(Project.KEYSTORE_FILENAME)) {
                localKeyStore.load(input, Project.KEYSTORE_PASSWORD);
            } catch (IOException e) {
                localKeyStore.load(null, Project.KEYSTORE_PASSWORD);
                try (FileOutputStream output = new FileOutputStream(Project.KEYSTORE_FILENAME)) {
                    localKeyStore.store(output, Project.KEYSTORE_PASSWORD);
                } catch (IOException e1) {
                    GuiInterfaceV1.reportError("Failed to load the local keystore!");
                }
            }
            return localKeyStore.aliases();
        } catch (Exception e) {
            GuiInterfaceV1.reportError(e);
            return null;
        }
    }

    @Override
    public void resetLocalKeystore() {
        try {
            Files.deleteIfExists(Paths.get(Project.KEYSTORE_FILENAME));
            loadLocalKeystore();
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to reset the local keystore!");
        }
    }

    // TODO: Fix this method!!!
    @Override
    public int loadKeypair(String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) localKeyStore.getCertificate(keypair_name);
            access.setVersion(cert.getVersion() - 1);
            access.setSubject(cert.getSubjectDN().toString());
            access.setIssuer(cert.getIssuerDN().toString());
            access.setNotBefore(cert.getNotBefore());
            access.setNotAfter(cert.getNotAfter());
            access.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
            access.setPublicKeyDigestAlgorithm(cert.getSigAlgName());
            access.setSerialNumber(cert.getSerialNumber().toString());
            // TODO: probably very bad thing this... fix and stuff...
            //if (cert.getKeyUsage()[5]) return 2; // CA certificate
            if (cert.getBasicConstraints() != -1) return 1; // User certificate
            return 0;
        } catch (KeyStoreException e) {
            access.reportError(e);
            return -1;
        }
    }

    @Override
    public boolean saveKeypair(String keypair_name) {
        if (!CertificateHelper.assertKeyPairParams(access))
            return false; // bad params
        int keySize = Integer.parseInt(access.getPublicKeyParameter());
        try {
            KeyPair pair = CertificateHelper.generateKeyPair(keySize);
            X509Certificate cert = CertificateHelper.generateSelfSignedCertificate(access, pair);
            Certificate[] chain = new Certificate[1];
            chain[0] = cert;
            localKeyStore.setKeyEntry(keypair_name, pair.getPrivate(), Project.KEYSTORE_PASSWORD, chain);
            return true;
        } catch (Exception e) {
            access.reportError(e);
            return false;
        }
    }

    @Override
    public boolean removeKeypair(String s) {
        return false;
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean exportKeypair(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean importCertificate(String s, String s1) {
        return false;
    }

    @Override
    public boolean exportCertificate(String s, String s1, int i, int i1) {
        return false;
    }

    @Override
    public boolean exportCSR(String s, String s1, String s2) {
        return false;
    }

    @Override
    public String importCSR(String s) {
        return null;
    }

    @Override
    public boolean signCSR(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean importCAReply(String s, String s1) {
        return false;
    }

    @Override
    public boolean canSign(String s) {
        return false;
    }

    @Override
    public String getSubjectInfo(String s) {
        return null;
    }

    @Override
    public String getCertPublicKeyAlgorithm(String s) {
        return null;
    }

    @Override
    public String getCertPublicKeyParameter(String s) {
        return null;
    }
}