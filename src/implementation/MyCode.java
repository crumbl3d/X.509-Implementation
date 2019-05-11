package implementation;

import code.*;
import gui.Constants;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import x509.v3.*;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class MyCode extends CodeV3 {

    private KeyStore keystore;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
        CertificateHelper.addBouncyCastleProvider();
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
            keystore = KeyStore.getInstance(Project.KEYSTORE_TYPE);
            try (FileInputStream input = new FileInputStream(Project.KEYSTORE_FILENAME)) {
                keystore.load(input, Project.KEYSTORE_PASSWORD);
            } catch (IOException e) {
                keystore.load(null, Project.KEYSTORE_PASSWORD);
                if (!saveLocalKeystore(false))
                    access.reportError("Failed to load the local keystore!");
            }
            return keystore.aliases();
        } catch (Exception e) {
            access.reportError(e);
            return null;
        }
    }

    public boolean saveLocalKeystore(boolean report) {
        try (FileOutputStream output = new FileOutputStream(Project.KEYSTORE_FILENAME)) {
            keystore.store(output, Project.KEYSTORE_PASSWORD);
            return true;
        } catch (Exception e) {
            if (report)
                access.reportError("Failed to save the local keystore!");
            return false;
        }
    }

    public void saveLocalKeystore() {
        saveLocalKeystore(true);
    }

    @Override
    public void resetLocalKeystore() {
        try {
            Files.deleteIfExists(Paths.get(Project.KEYSTORE_FILENAME));
            loadLocalKeystore();
        } catch (IOException e) {
            access.reportError("Failed to reset the local keystore!");
        }
    }

    // TODO: Fix this method!!!
    @Override
    public int loadKeypair(String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
            X509CertificateHolder holder = new JcaX509CertificateHolder(cert);
            access.setSubject(holder.getSubject().toString());
            access.setIssuer(holder.getIssuer().toString());
            access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
            access.setVersion(holder.getVersionNumber() - 1);
            access.setSerialNumber(holder.getSerialNumber().toString());
            access.setNotBefore(holder.getNotBefore());
            access.setNotAfter(holder.getNotAfter());
            String algorithm = cert.getPublicKey().getAlgorithm();
            access.setPublicKeyAlgorithm(algorithm);
            if (algorithm.equals("DSA"))
                access.setPublicKeyParameter(Integer.toString(((DSAPublicKey) cert.getPublicKey()).getParams().getP().bitLength()));
            else if (algorithm.equals("RSA"))
                access.setPublicKeyParameter(Integer.toString(((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength()));
            else if (algorithm.equals("EC"))
                access.setPublicKeyECCurve(((ECPublicKey) cert.getPublicKey()).getParams().getCurve().toString());
            access.setPublicKeyDigestAlgorithm(cert.getSigAlgName());
            Extension authorityKeyIdentifier = holder.getExtension(Extension.authorityKeyIdentifier);
            if (authorityKeyIdentifier != null) {
                access.setCritical(Constants.AKID, authorityKeyIdentifier.isCritical());
                byte[] akiValue = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
                ASN1OctetString akiOc = ASN1OctetString.getInstance(akiValue);
                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(akiOc.getOctets());
                if (aki != null) {
                    if (aki.getAuthorityCertSerialNumber() != null)
                        access.setAuthoritySerialNumber(aki.getAuthorityCertSerialNumber().toString());
                    if (aki.getAuthorityCertIssuer() != null)
                        access.setAuthorityIssuer(aki.getAuthorityCertIssuer().toString());
                    if (aki.getAuthorityCertSerialNumber() != null)
                        access.setAuthorityKeyID(aki.getAuthorityCertSerialNumber().toString());
                }
            }
            Extension issuerAlternativeName = holder.getExtension(Extension.issuerAlternativeName);
            if (issuerAlternativeName != null) {
                access.setCritical(Constants.IAN, issuerAlternativeName.isCritical());
                access.setAlternativeName(Constants.IAN, issuerAlternativeName.toString());
            }
            Extension extendedKeyUsage = holder.getExtension(Extension.extendedKeyUsage);
            if (extendedKeyUsage != null) {
                access.setCritical(Constants.EKU, extendedKeyUsage.isCritical());
////            access.setExtendedKeyUsage(cert.getExtendedKeyUsage());
            }
            boolean[] vector = cert.getKeyUsage();
            if (vector == null)
                return 0;
            if (vector[5]) // keyCertSign
                return 2;
            // TODO: Check if certificate is signed or not?!? self-signed or something else?
            return 0;
        } catch (KeyStoreException | CertificateEncodingException e) {
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
            KeyPair pair = CertificateHelper.generateKeyPair(access.getPublicKeyAlgorithm(), keySize);
            X509Certificate cert = CertificateHelper.generateSelfSignedCertificate(access, pair);
            Certificate[] chain = new Certificate[1];
            chain[0] = cert;
            keystore.setKeyEntry(keypair_name, pair.getPrivate(), Project.KEY_PASSWORD, chain);
            saveLocalKeystore();
            return true;
        } catch (Exception e) {
            access.reportError(e);
            return false;
        }
    }

    @Override
    public boolean removeKeypair(String keypair_name) {
        try {
            keystore.deleteEntry(keypair_name);
            saveLocalKeystore();
            return true;
        } catch (KeyStoreException e) {
            access.reportError(e);
            return false;
        }
    }

    @Override
    public boolean importKeypair(String keypair_name, String file, String password) {
        try (FileInputStream input = new FileInputStream(file)) {
            KeyStore importStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            importStore.load(input, password.toCharArray());
            Enumeration<String> aliases = importStore.aliases();
            if (!aliases.hasMoreElements()) {
                access.reportError("Selected keystore is empty!");
                return false;
            }
            String alias = aliases.nextElement();
            keystore.setKeyEntry(keypair_name, importStore.getKey(alias, password.toCharArray()),
                    password.toCharArray(), importStore.getCertificateChain(alias));
            saveLocalKeystore();
            return true;
        } catch (Exception e) {
            access.reportError(e);
            return false;
        }
    }

    @Override
    public boolean exportKeypair(String keypair_name, String file, String password) {
        try (FileOutputStream output = new FileOutputStream(file)) {
            KeyStore exportStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            exportStore.load(null, password.toCharArray());
            exportStore.setKeyEntry(keypair_name, keystore.getKey(keypair_name, Project.KEY_PASSWORD),
                    password.toCharArray(), keystore.getCertificateChain(keypair_name));
            exportStore.store(output, password.toCharArray());
            return true;
        } catch (Exception e) {
            access.reportError(e);
            return false;
        }
    }

    @Override
    public boolean importCertificate(String file, String keypair_name) {
        try (FileInputStream input = new FileInputStream(file)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            X509Certificate cert = (X509Certificate) factory.generateCertificate(input);
            keystore.setCertificateEntry(keypair_name, cert);
            saveLocalKeystore();
            return true;
        } catch (Exception e) {
            access.reportError(e);
            return false;
        }
    }

    @Override
    public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
        try {
            if (format == 0) { // head-only
                Certificate cert = keystore.getCertificate(keypair_name);
                if (encoding == 0) { // DER
                } else { // PEM
                    JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(new File(file)));
                    writer.writeObject(cert);
                    writer.close();
                }
            } else {
                Certificate[] chain = keystore.getCertificateChain(keypair_name);
                if (encoding == 0) { // DER

                } else { // PEM

                }
            }
            return true;
        } catch (Exception e) {
            access.reportError(e);
            return false;
        }
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
    public boolean canSign(String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
            boolean[] vector = cert.getKeyUsage();
            if (vector == null)
                return false;
            return vector[5]; // keyCertSign
        } catch (KeyStoreException e) {
            access.reportError(e);
            return false;
        }
    }

    @Override
    public String getSubjectInfo(String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
            return cert.getSubjectX500Principal().getName();
        } catch (KeyStoreException e) {
            access.reportError(e);
            return null;
        }
    }

    @Override
    public String getCertPublicKeyAlgorithm(String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
            System.out.println("requested algorithm: " + cert.getPublicKey().getAlgorithm());
            return cert.getPublicKey().getAlgorithm();
        } catch (KeyStoreException e) {
            access.reportError(e);
            return null;
        }
    }

    @Override
    public String getCertPublicKeyParameter(String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
            String algorithm = cert.getPublicKey().getAlgorithm();
            if (algorithm.equals("DSA"))
                return Integer.toString(((DSAPublicKey) cert.getPublicKey()).getParams().getP().bitLength());
            else if (algorithm.equals("RSA"))
                return Integer.toString(((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength());
            else if (algorithm.equals("EC"))
                return ((ECPublicKey) cert.getPublicKey()).getParams().getCurve().toString();
            return null;
        } catch (KeyStoreException e) {
            access.reportError(e);
            return null;
        }
    }
}