package implementation;

import code.GuiException;
import gui.Constants;
import gui.GuiInterfaceV1;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import x509.v3.CodeV3;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

@SuppressWarnings("unused")
public class MyCode extends CodeV3 {

    private KeyStore keystore;

    private final boolean supportsDSA;
    private final boolean supportsRSA;
    private final boolean supportsEC;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
        supportsDSA = algorithm_conf[0];
        supportsRSA = algorithm_conf[1];
        supportsEC = algorithm_conf[3];
        Security.addProvider(new BouncyCastleProvider());
    }

    private boolean saveLocalKeystore(boolean report) {
        try (FileOutputStream output = new FileOutputStream(Project.KEYSTORE_FILENAME)) {
            keystore.store(output, Project.KEYSTORE_PASSWORD);
            return true;
        } catch (Exception e) {
            if (report)
                GuiInterfaceV1.reportError("Failed to save the local keystore!");
            return false;
        }
    }

    private void saveLocalKeystore() {
        saveLocalKeystore(true);
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
                    GuiInterfaceV1.reportError("Failed to load the local keystore!");
            }
            return keystore.aliases();
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

    @Override
    public int loadKeypair(String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);

            // --- Version panel ---
            access.setVersion(cert.getVersion() - 1); // Certificate version

            // --- Serial number panel ---
            access.setSerialNumber(cert.getSerialNumber().toString()); // Serial number panel

            // --- Validity panel ---
            access.setNotBefore(cert.getNotBefore()); // Not before date
            access.setNotAfter(cert.getNotAfter()); // Not after date

            // --- Public key panel ---
            PublicKey publicKey = cert.getPublicKey();
            String algorithm = publicKey.getAlgorithm();

            boolean validDSA = algorithm.equals("DSA") && supportsDSA,
                    validRSA = algorithm.equals("RSA") && supportsRSA,
                    validEC = algorithm.equals("EC") && supportsEC;

            if (validDSA || validRSA || validEC) {
                access.setPublicKeyAlgorithm(algorithm); // Public key algorithm
                access.setPublicKeyDigestAlgorithm(cert.getSigAlgName()); // Signature algorithm
                if (validDSA) // DSA
                    access.setPublicKeyParameter(Integer.toString(((DSAPublicKey) publicKey).getParams().getP().bitLength()));
                else if (validRSA) // RSA
                    access.setPublicKeyParameter(Integer.toString(((RSAPublicKey) publicKey).getModulus().bitLength()));
                else { // EC
                    // not completely implemented, not necessary for this project
                    access.setPublicKeyParameter("not implemented");
                    access.setPublicKeyECCurve(((ECPublicKey) publicKey).getParams().getCurve().toString());
                }
            }

            // --- Subject panel ---
            access.setSubject(cert.getSubjectX500Principal().getName()); // Subject info
            access.setSubjectSignatureAlgorithm(cert.getPublicKey().getAlgorithm()); // Public key algorithm

            // --- Issuer panel ---
            access.setIssuer(cert.getIssuerX500Principal().getName()); // Issuer info
            access.setIssuerSignatureAlgorithm(CertificateHelper.getSignatureAlgorithm(cert)); // Signature algorithm

            // --- Extensions panel ---
            X509CertificateHolder holder = new JcaX509CertificateHolder(cert);

            // Authority key identifier
            Extension authorityKeyIdentifier = holder.getExtension(Extension.authorityKeyIdentifier);
            access.setEnabledAuthorityKeyID(authorityKeyIdentifier != null);
            if (authorityKeyIdentifier != null) {
                access.setCritical(Constants.AKID, authorityKeyIdentifier.isCritical());
                byte[] akiValue = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
                ASN1OctetString akiOc = ASN1OctetString.getInstance(akiValue);
                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(akiOc.getOctets());
                if (aki != null) {
                    if (aki.getAuthorityCertSerialNumber() != null)
                        access.setAuthoritySerialNumber(aki.getAuthorityCertSerialNumber().toString());
                    if (aki.getAuthorityCertIssuer() != null) {
                        StringBuilder sb = new StringBuilder();
                        for (GeneralName gn : aki.getAuthorityCertIssuer().getNames())
                            sb.append(gn.getName());
                        access.setAuthorityIssuer(sb.toString());
                    }
                    if (aki.getAuthorityCertSerialNumber() != null)
                        access.setAuthorityKeyID(aki.getAuthorityCertSerialNumber().toString());
                }
            }

            // Issuer alternative name
            Extension issuerAlternativeName = holder.getExtension(Extension.issuerAlternativeName);
            if (issuerAlternativeName != null) {
                access.setCritical(Constants.IAN, issuerAlternativeName.isCritical());
                access.setAlternativeName(Constants.IAN, issuerAlternativeName.toString());
            }

            // Extended key usage
            Extension extendedKeyUsage = holder.getExtension(Extension.extendedKeyUsage);
            if (extendedKeyUsage != null) {
                access.setCritical(Constants.EKU, extendedKeyUsage.isCritical());
                access.setExtendedKeyUsage(CertificateHelper.getGuiUsageVector(
                        ExtendedKeyUsage.fromExtensions(holder.getExtensions())));
            }

            // Checking if certificate is valid
            try {
                cert.checkValidity();
            } catch (CertificateNotYetValidException | CertificateExpiredException e) {
                return 0; // Invalid certificate!
            }

            // Checking if certificate is self-signed
            boolean selfSigned = false;
            if (cert.getSubjectDN().equals(cert.getIssuerDN())) {
                try {
                    cert.verify(cert.getPublicKey(), BouncyCastleProvider.PROVIDER_NAME);
                    selfSigned = true;
                } catch (Exception e) {
                    return 0;
                }
            }

            // Checking if certificate is CA certificate
            boolean[] keyUsageVector = cert.getKeyUsage();
            if (keyUsageVector != null && keyUsageVector[5] || cert.getBasicConstraints() != -1)
                return 2; // CA certificate
            else if (!selfSigned)
                return 1; // CA signed certificate
            return 0; // Self-signed certificate
        } catch (KeyStoreException | CertificateEncodingException e) {
            GuiInterfaceV1.reportError(e);
            return -1;
        }
    }

    @Override
    public boolean saveKeypair(String keypair_name) {
        if (access.getVersion() != Project.CERTIFICATE_VERSION) {
            GuiInterfaceV1.reportError("Unsupported certificate version: " + (access.getVersion() + 1));
            return false;
        }
        if (!access.getPublicKeyAlgorithm().equals(Project.PUBLIC_KEY_ALGORITHM)) {
            GuiInterfaceV1.reportError("Unsupported public key algorithm: " + access.getPublicKeyAlgorithm());
            return false;
        }
        if (!access.getPublicKeyDigestAlgorithm().equals(Project.DIGEST_ALGORITHM)) {
            GuiInterfaceV1.reportError("Unsupported public key digest algorithm: " + access.getPublicKeyDigestAlgorithm());
            return false;
        }
        boolean cond = false;
        for (String param : Project.PUBLIC_KEY_SIZES) {
            if (cond = param.equals(access.getPublicKeyParameter()))
                break;
        }
        if (!cond) {
            GuiInterfaceV1.reportError("Unsupported public key algorithm parameter: " + access.getPublicKeyParameter());
            return false;
        }
        int keySize = Integer.parseInt(access.getPublicKeyParameter());
        try {
            KeyPair pair = CertificateHelper.generateKeyPair(access.getPublicKeyAlgorithm(), keySize);

            X509v3CertificateBuilder certBuilder = CertificateHelper.initCertificateBuilder(
                    access.getSubject(), access.getSubject(), pair.getPublic(),
                    new BigInteger(access.getSerialNumber()), access.getNotBefore(), access.getNotAfter());

            if (access.getEnabledAuthorityKeyID())
                CertificateHelper.addAuthorityKeyIdentifier(
                        certBuilder, access.isCritical(Constants.AKID),
                        pair.getPublic(), access.getSubject(), new BigInteger(access.getSerialNumber()));

            if (access.getAlternativeName(Constants.IAN).length > 0)
                CertificateHelper.addIssuerAlternativeName(
                        certBuilder, access.isCritical(Constants.IAN), access.getAlternativeName(Constants.IAN));

            boolean extendedKeyUsage = false;
            for (boolean flag : access.getExtendedKeyUsage())
                if (flag) {
                    extendedKeyUsage = true;
                    break;
                }
            if (extendedKeyUsage)
                CertificateHelper.addExtendedKeyUsage(
                        certBuilder, access.isCritical(Constants.EKU), access.getExtendedKeyUsage());

            X509Certificate cert = CertificateHelper.generateSignedCertificate(
                    certBuilder, access.getPublicKeyDigestAlgorithm(), pair.getPrivate());

            Certificate[] chain = new Certificate[] {cert};
            keystore.setKeyEntry(keypair_name, pair.getPrivate(), Project.KEY_PASSWORD, chain);
            saveLocalKeystore();
            return true;
        } catch (Exception e) {
            GuiInterfaceV1.reportError(e);
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
            GuiInterfaceV1.reportError(e);
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
                GuiInterfaceV1.reportError("Selected keystore is empty!");
                return false;
            }
            String alias = aliases.nextElement();
            keystore.setKeyEntry(keypair_name, importStore.getKey(alias, password.toCharArray()),
                    password.toCharArray(), importStore.getCertificateChain(alias));
            saveLocalKeystore();
            return true;
        } catch (Exception e) {
            GuiInterfaceV1.reportError(e);
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
            GuiInterfaceV1.reportError(e);
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
            GuiInterfaceV1.reportError(e);
            return false;
        }
    }

    // TODO: Finish this method!
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
            GuiInterfaceV1.reportError(e);
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
            boolean[] keyUsageVector = cert.getKeyUsage(); // keyUsageVector[5] - keyCertSign
            return keyUsageVector != null && keyUsageVector[5] || cert.getBasicConstraints() != -1;
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError(e);
            return false;
        }
    }

    @Override
    public String getSubjectInfo(String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
            return cert.getSubjectX500Principal().getName();
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError(e);
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
            GuiInterfaceV1.reportError(e);
            return null;
        }
    }

    @Override
    public String getCertPublicKeyParameter(String keypair_name) {
        try {
            X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
            String algorithm = cert.getPublicKey().getAlgorithm();
            switch (algorithm) {
                case "DSA":
                    return Integer.toString(((DSAPublicKey) cert.getPublicKey()).getParams().getP().bitLength());
                case "RSA":
                    return Integer.toString(((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength());
                case "EC":
                    return ((ECPublicKey) cert.getPublicKey()).getParams().getCurve().toString();
            }
            return null;
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError(e);
            return null;
        }
    }
}