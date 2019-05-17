package implementation;

import code.GuiException;
import gui.Constants;
import gui.GuiInterfaceV1;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.Store;
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
import java.util.*;

@SuppressWarnings("unused")
public class MyCode extends CodeV3 {

    private KeyStore keystore;

    private final boolean supportsDSA;
    private final boolean supportsRSA;
    private final boolean supportsEC;

    private JcaPKCS10CertificationRequest jcaRequest; // last sent request

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
        supportsDSA = algorithm_conf[0];
        supportsRSA = algorithm_conf[1];
        supportsEC = algorithm_conf[3];
        jcaRequest = null;
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

    private PKCS10CertificationRequest loadCSR(String file) {
        try {
            PEMParser parser = new PEMParser(new FileReader(new File(file)));
            return (PKCS10CertificationRequest) parser.readObject();
        } catch (FileNotFoundException e) {
            GuiInterfaceV1.reportError("Failed to open " + file + "!");
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to parse " + file + "!");
        }
        return null;
    }

    private Certificate[] getCertificateChain(String keypair_name) {
        Certificate[] caChain;
        try {
            caChain = keystore.getCertificateChain(keypair_name);
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError("Failed to load certificate chain with alias: " + keypair_name + "!");
            return null;
        }
        if (caChain == null)
            GuiInterfaceV1.reportError("Local keystore does not contain a certificate chain with the following alias: " + keypair_name);
        return caChain;
    }

    private X509Certificate getCertificate(String keypair_name) {
        X509Certificate cert;
        try {
            cert = (X509Certificate) keystore.getCertificate(keypair_name);
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError("Failed to load certificate with alias: " + keypair_name + "!");
            return null;
        }
        if (cert == null)
            GuiInterfaceV1.reportError("Local keystore does not contain a certificate with the following alias: " + keypair_name);
        return cert;
    }

    private PrivateKey getPrivateKey(String keypair_name) {
        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) keystore.getKey(keypair_name, Project.KEY_PASSWORD);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            GuiInterfaceV1.reportError("Failed to load private key with alias: " + keypair_name + "!");
            return null;
        }
        if (privateKey == null)
            GuiInterfaceV1.reportError("Local keystore does not contain a private key with the following alias: " + keypair_name);
        return privateKey;
    }

    public static Certificate[] establishCertChain(Certificate userCert, Certificate replyCert) {
        Certificate[] chain = new Certificate[] {replyCert}; // temp
        return chain;
    }

    public static Certificate[] validateReply(String keypair_name, Certificate userCert, Certificate[] replyCerts) {
        int i;
        PublicKey userPU = userCert.getPublicKey();
        for (i = 0; i < replyCerts.length; ++i) {
            if (userPU.equals(replyCerts[i].getPublicKey()))
                break;
        }

        if (i == replyCerts.length) {
            GuiInterfaceV1.reportError("CA reply does not contain the public key for the alias: " + keypair_name + "!");
            return null;
        }

        Certificate temp = replyCerts[0];
        replyCerts[0] = replyCerts[i];
        replyCerts[i] = temp;

        X509Certificate thisCert = (X509Certificate) replyCerts[0];

        for (i = 1; i < replyCerts.length; ++i) {
            int j;
            for (j = i; j < replyCerts.length; ++j) {
                if (CertificateHelper.signedBy(thisCert, (X509Certificate) replyCerts[j])) {
                    temp = replyCerts[i];
                    replyCerts[i] = replyCerts[j];
                    replyCerts[j] = temp;
                    thisCert = (X509Certificate) replyCerts[i];
                    break;
                }
            }
            if (j == replyCerts.length) {
                GuiInterfaceV1.reportError("Incomplete certificate chain in CA reply!");
                return null;
            }
        }

        return replyCerts; // temp
    }

    private void populateExtensionsPanel(Extensions extensions) {
        if (extensions == null)
            return;
        // Authority key identifier
        Extension authorityKeyIdentifier = extensions.getExtension(Extension.authorityKeyIdentifier);
        access.setEnabledAuthorityKeyID(authorityKeyIdentifier != null);
        if (authorityKeyIdentifier != null) {
            access.setCritical(Constants.AKID, authorityKeyIdentifier.isCritical());
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(extensions);
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
        Extension issuerAlternativeName = extensions.getExtension(Extension.issuerAlternativeName);
        if (issuerAlternativeName != null) {
            access.setCritical(Constants.IAN, issuerAlternativeName.isCritical());
            access.setAlternativeName(Constants.IAN, issuerAlternativeName.toString());
        }

        // Extended key usage
        Extension extendedKeyUsage = extensions.getExtension(Extension.extendedKeyUsage);
        if (extendedKeyUsage != null) {
            access.setCritical(Constants.EKU, extendedKeyUsage.isCritical());
            access.setExtendedKeyUsage(CertificateHelper.getGuiUsageVector(
                    ExtendedKeyUsage.fromExtensions(extensions)));
        }
    }

    private static boolean writeDER(OutputStream out, byte[] encoded) {
        try (ASN1InputStream asn1 = new ASN1InputStream(encoded)) {
            DEROutputStream dos = new DEROutputStream(out);
            dos.writeObject(asn1.readObject());
            dos.flush();
            dos.close();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static boolean writePEM(Writer writer, Object data) {
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(new JcaMiscPEMGenerator(data));
            pemWriter.flush();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            keystore = KeyStore.getInstance(Project.KEYSTORE_TYPE, BouncyCastleProvider.PROVIDER_NAME);
            try (FileInputStream input = new FileInputStream(Project.KEYSTORE_FILENAME)) {
                keystore.load(input, Project.KEYSTORE_PASSWORD);
            } catch (IOException e) {
                keystore.load(null, Project.KEYSTORE_PASSWORD);
                if (!saveLocalKeystore(false))
                    GuiInterfaceV1.reportError("Failed to load the local keystore!");
            }
            return keystore.aliases();
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to open " + Project.KEYSTORE_FILENAME + "!");
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException e) {
            GuiInterfaceV1.reportError("Failed to initialize a PKCS12 keystore with: " + Project.KEYSTORE_FILENAME + "!");
        }
        return null;
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
        X509Certificate cert = getCertificate(keypair_name);
        if (cert == null)
            return -1;

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
        X509CertificateHolder holder;
        try {
            holder = new JcaX509CertificateHolder(cert);
        } catch (CertificateEncodingException e) {
            return -1;
        }
        populateExtensionsPanel(holder.getExtensions());

        // Checking if certificate is valid
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException e) {
            GuiInterfaceV1.reportError("Certificate: " + keypair_name + " has expired!");
            return 0;
        } catch (CertificateNotYetValidException e) {
            GuiInterfaceV1.reportError("Certificate: " + keypair_name + " is not yet valid!");
            return 0;
        }

        // Checking if certificate is CA certificate
        boolean[] keyUsageVector = cert.getKeyUsage();
        if (keyUsageVector != null && keyUsageVector[5] || cert.getBasicConstraints() != -1)
            return 2; // CA certificate
        else if (!CertificateHelper.selfSigned(cert))
            return 1; // CA signed certificate
        return 0; // Self-signed certificate
    }

    @Override
    public boolean saveKeypair(String keypair_name) {
        if (access.getVersion() != Project.CERTIFICATE_VERSION) {
            GuiInterfaceV1.reportError("Unsupported certificate version: " + (access.getVersion() + 1) + "!");
            return false;
        }
        if (!access.getPublicKeyAlgorithm().equals(Project.PUBLIC_KEY_ALGORITHM)) {
            GuiInterfaceV1.reportError("Unsupported public key algorithm: " + access.getPublicKeyAlgorithm() + "!");
            return false;
        }
        if (!access.getPublicKeyDigestAlgorithm().equals(Project.DIGEST_ALGORITHM)) {
            GuiInterfaceV1.reportError("Unsupported public key digest algorithm: " + access.getPublicKeyDigestAlgorithm() + "!");
            return false;
        }
        boolean cond = false;
        for (String param : Project.PUBLIC_KEY_SIZES) {
            if (cond = param.equals(access.getPublicKeyParameter()))
                break;
        }
        if (!cond) {
            GuiInterfaceV1.reportError("Unsupported public key algorithm parameter: " + access.getPublicKeyParameter() + "!");
            return false;
        }

        KeyPair pair;
        try {
            pair = CertificateHelper.generateKeyPair(access.getPublicKeyAlgorithm(),
                    Integer.parseInt(access.getPublicKeyParameter()));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            GuiInterfaceV1.reportError("Failed to generate a keypair with " + access.getPublicKeyAlgorithm() + "!");
            return false;
        }

        X509v3CertificateBuilder certBuilder = CertificateHelper.initCertificateBuilder(
                access.getSubject(), access.getSubject(), pair.getPublic(),
                new BigInteger(access.getSerialNumber()), access.getNotBefore(), access.getNotAfter());

        if (certBuilder == null) {
            GuiInterfaceV1.reportError("Failed to initialize the certificate builder!");
            return false;
        }

        if (access.getEnabledAuthorityKeyID()) {
            try {
                CertificateHelper.addAuthorityKeyIdentifier(
                        certBuilder, access.isCritical(Constants.AKID),
                        pair.getPublic(), access.getSubject(), new BigInteger(access.getSerialNumber()));
            } catch (NoSuchAlgorithmException | CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add authority key identifier!");
                return false;
            }
        }

        if (access.getAlternativeName(Constants.IAN).length > 0) {
            try {
                CertificateHelper.addIssuerAlternativeName(
                        certBuilder, access.isCritical(Constants.IAN), access.getAlternativeName(Constants.IAN));
            } catch (CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add issuer alternative name!");
                return false;
            }
        }

        boolean extendedKeyUsage = false;
        for (boolean flag : access.getExtendedKeyUsage())
            if (flag) {
                extendedKeyUsage = true;
                break;
            }
        if (extendedKeyUsage) {
            try {
                CertificateHelper.addExtendedKeyUsage(
                        certBuilder, access.isCritical(Constants.EKU), access.getExtendedKeyUsage());
            } catch (CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add extended key usage!");
                return false;
            }
        }

        X509Certificate cert;
        try {
            cert = CertificateHelper.generateSignedCertificate(
                    certBuilder, access.getPublicKeyDigestAlgorithm(), pair.getPrivate());
        } catch (OperatorCreationException | CertificateException e) {
            GuiInterfaceV1.reportError("Failed to generate the certificate!");
            return false;
        }

        if (cert == null)
            return false;

        try {
            keystore.setKeyEntry(keypair_name, pair.getPrivate(), Project.KEY_PASSWORD, new Certificate[]{cert});
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError("Failed to save the generated keypair!");
            return false;
        }
        saveLocalKeystore();
        return true;
    }

    @Override
    public boolean removeKeypair(String keypair_name) {
        try {
            keystore.deleteEntry(keypair_name);
            saveLocalKeystore();
            return true;
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError("Failed to remove keypair with alias " + keypair_name + "!");
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
            String alias = aliases.nextElement(); // Importing only the first keypair (expecting there is only one)
            keystore.setKeyEntry(keypair_name, importStore.getKey(alias, password.toCharArray()),
                    password.toCharArray(), importStore.getCertificateChain(alias));
            saveLocalKeystore();
            return true;
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to open " + file + "!");
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException e) {
            GuiInterfaceV1.reportError("Failed to initialize a PKCS12 keystore with: " + file + "!");
        } catch (UnrecoverableKeyException e) {
            GuiInterfaceV1.reportError("Failed to get a private key from: " + file + "!");
        }
        return false;
    }

    @Override
    public boolean exportKeypair(String keypair_name, String file, String password) {
        Certificate[] chain = getCertificateChain(keypair_name);
        if (chain == null)
            return false;
        PrivateKey privateKey = getPrivateKey(keypair_name);
        if (privateKey == null)
            return false;
        try (FileOutputStream output = new FileOutputStream(file)) {
            KeyStore exportStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            exportStore.load(null, password.toCharArray());
            exportStore.setKeyEntry(keypair_name, privateKey, password.toCharArray(), chain);
            exportStore.store(output, password.toCharArray());
            return true;
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to open " + file + "!");
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException e) {
            GuiInterfaceV1.reportError("Failed to initialize a PKCS12 keystore with: " + file + "!");
        }
        return false;
    }

    @Override
    public boolean importCertificate(String file, String keypair_name) {
        try (FileInputStream input = new FileInputStream(file)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            X509Certificate cert = (X509Certificate) factory.generateCertificate(input);
            keystore.setCertificateEntry(keypair_name, cert);
            saveLocalKeystore();
            return true;
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to open " + file + "!");
        } catch (NoSuchProviderException | CertificateException e) {
            GuiInterfaceV1.reportError("Failed to generate a certificate from: " + file + "!");
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError("Failed to save the imported certificate!");
        }
        return false;
    }

    // TODO: Finish this method!
    @Override
    public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
        try {
            if (format == 0) { // head-only
                X509Certificate cert = getCertificate(keypair_name);
                if (cert == null)
                    return false;
                if (encoding == 0) { // DER
                    return writeDER(new FileOutputStream(file), cert.getEncoded());
                } else { // PEM
                    return writePEM(new FileWriter(new File(file)), cert);
                }
            } else { // entire chain
                Certificate[] chain = keystore.getCertificateChain(keypair_name);
//                if (encoding == 0) { // DER
//
//                } else { // PEM
//
//                }
            }
            return true;
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to open " + file + "!");
        } catch (Exception e) {
            GuiInterfaceV1.reportError("Failed to load keypair: " + keypair_name + "!");
        }
        return false;
    }

    @Override
    public boolean exportCSR(String file, String keypair_name, String algorithm) {
        X509Certificate cert = getCertificate(keypair_name);
        if (cert == null)
            return false;
        PrivateKey privateKey = getPrivateKey(keypair_name);
        if (privateKey == null)
            return false;
        PKCS10CertificationRequest request;
        try {
            request = CertificateHelper.generateCSR(cert, privateKey, algorithm);
        } catch (CertificateEncodingException | OperatorCreationException e) {
            GuiInterfaceV1.reportError("Failed to generate the certification request!");
            return false;
        }
        try {
            return writePEM(new FileWriter(new File(file)), request);
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to write the certification request to " + file + "!");
        }
        return false;
    }

    @Override
    public String importCSR(String file) {
        PKCS10CertificationRequest request = loadCSR(file);
        if (request == null)
            return null;
        this.jcaRequest = new JcaPKCS10CertificationRequest(request);
        // TODO: Stupid GUI code annihilates whatever is set to extensions panel... whats the point of extensions then?
        // populateExtensionsPanel(CertificateHelper.getExtensionsFromCSR(request));
        return request.getSubject().toString();
    }

    @Override
    public boolean signCSR(String file, String keypair_name, String algorithm) {
        Certificate[] issuerChain = getCertificateChain(keypair_name);
        if (issuerChain == null || issuerChain.length <= 0)
            return false;

        X509Certificate issuer = (X509Certificate) issuerChain[0];
        if (issuer == null)
            return false;
        try {
            issuer.checkValidity();
        } catch (CertificateExpiredException e) {
            GuiInterfaceV1.reportError("CA certificate: " + keypair_name + " has expired and cannot be used to sign a CSR!");
            return false;
        } catch (CertificateNotYetValidException e) {
            GuiInterfaceV1.reportError("CA certificate: " + keypair_name + " is not yet valid and cannot be used to sign a CSR!");
            return false;
        }
        PrivateKey issuerPrivateKey = getPrivateKey(keypair_name);
        if (issuerPrivateKey == null)
            return false;

//        JcaX509CertificateHolder jcaIssuer;
////        try {
////            jcaIssuer = new JcaX509CertificateHolder(issuer);
////        } catch (CertificateEncodingException e) {
////            return false;
////        }

        if (jcaRequest == null)
            return false;

        X509v3CertificateBuilder certBuilder;
        try {
             certBuilder = CertificateHelper.initCertificateBuilder(
                    access.getIssuer(), access.getSubject(),
                    jcaRequest.getPublicKey(), new BigInteger(access.getSerialNumber()),
                    access.getNotBefore(), access.getNotAfter());
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            return false;
        }
        if (certBuilder == null) {
            GuiInterfaceV1.reportError("Failed to initialize the certificate builder!");
            return false;
        }

        if (access.getEnabledAuthorityKeyID()) {
            try {
                CertificateHelper.addAuthorityKeyIdentifier(certBuilder, access.isCritical(Constants.AKID), issuer);
            } catch (NoSuchAlgorithmException | CertificateEncodingException | CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add authority key identifier!");
                return false;
            }
        }

        if (access.getAlternativeName(Constants.IAN).length > 0) {
            try {
                CertificateHelper.addIssuerAlternativeName(
                        certBuilder, access.isCritical(Constants.IAN), access.getAlternativeName(Constants.IAN));
            } catch (CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add issuer alternative name!");
                return false;
            }
        }

        boolean extendedKeyUsage = false;
        for (boolean flag : access.getExtendedKeyUsage())
            if (flag) {
                extendedKeyUsage = true;
                break;
            }
        if (extendedKeyUsage) {
            try {
                CertificateHelper.addExtendedKeyUsage(
                        certBuilder, access.isCritical(Constants.EKU), access.getExtendedKeyUsage());
            } catch (CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add extended key usage!");
                return false;
            }
        }

        X509Certificate cert;
        try {
            cert = CertificateHelper.generateSignedCertificate(
                    certBuilder, algorithm, issuerPrivateKey);
        } catch (OperatorCreationException | CertificateException e) {
            GuiInterfaceV1.reportError("Failed to generate the certificate!");
            return false;
        }

        Store certs;

        List<Certificate> chain = new ArrayList<>(Arrays.asList(issuerChain));

        try {
            certs = new JcaCertStore(chain);
        } catch (CertificateEncodingException e) {
            return false;
        }

        CMSSignedDataGenerator cmsGen = new CMSSignedDataGenerator();

        ContentSigner signer;
        try {
            signer = new JcaContentSignerBuilder(algorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerPrivateKey);
        } catch (OperatorCreationException e) {
            return false;
        }

        try {
            cmsGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build()).build(signer, issuer));
        } catch (OperatorCreationException | CertificateEncodingException e) {
            return false;
        }
        try {
            cmsGen.addCertificate(new JcaX509CertificateHolder(cert));
            cmsGen.addCertificates(certs);
        } catch (CMSException | CertificateEncodingException e) {
            return false;
        }

        CMSTypedData chainMessage = new CMSProcessableByteArray("chain".getBytes());
        CMSSignedData sigData;
        try {
            sigData = cmsGen.generate(chainMessage, false);
        } catch (CMSException e) {
            return false;
        }

        try {
//            writeDER(new FileOutputStream(file), sigData.getEncoded());
        writePEM(new FileWriter(new File(file)), sigData.toASN1Structure());
    } catch (IOException e) {
        return false;
    }

        return true;
}

    @Override
    public boolean importCAReply(String file, String keypair_name) {
        X509Certificate userCert = getCertificate(keypair_name);
        if (userCert == null)
            return false;

        CertificateFactory factory;
        try {
            factory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        } catch (CertificateException | NoSuchProviderException e) {
            return false;
        }

        Collection<? extends Certificate> c;
        try {
            c = factory.generateCertificates(new FileInputStream(new File(file)));
        } catch (CertificateException | FileNotFoundException e) {
            return false;
        }

        if (c.isEmpty())
            return false;

        Certificate[] replyCerts = c.toArray(new Certificate[c.size()]);
        Certificate[] newChain;

        for (Certificate ce : replyCerts)
            System.out.println(ce);

        if (replyCerts.length == 1) { // single-cert reply
            newChain = establishCertChain(userCert, replyCerts[0]);
        } else { // cert-chain reply (e.g., PKCS#7)
            newChain = validateReply(keypair_name, userCert, replyCerts);
        }

        if (newChain == null)
            return false;

        try {
            keystore.setKeyEntry(keypair_name, getPrivateKey(keypair_name), Project.KEY_PASSWORD, newChain);
        } catch (KeyStoreException e) {
            return false;
        }
        saveLocalKeystore();
        return true;

//        try {
//            PEMParser parser = new PEMParser(new FileReader(new File(file)));
//            ContentInfo info = (ContentInfo) parser.readObject();
//            CMSSignedData data = new CMSSignedData(info);
//            Store certs = data.getCertificates();
//            SignerInformationStore signers = data.getSignerInfos();
//
//            Collection c = signers.getSigners();
//            Iterator it = c.iterator();
//
//            while (it.hasNext()) {
//                SignerInformation signer = (SignerInformation) it.next();
//                Collection certCollection = certs.getMatches(signer.getSID());
//
//                Iterator certIt = certCollection.iterator();
//
//                while (certIt.hasNext()) {
//                    X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
//                    X509Certificate xcert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(cert);
//                    System.out.println(xcert);
//                }
//
////                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(cert))) {
////                    X509Certificate xcert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(cert);
////                    System.out.println(xcert);
////                }
//            }
//
//        } catch (FileNotFoundException e) {
//            GuiInterfaceV1.reportError("Failed to open " + file + "!");
//        } catch (IOException e) {
//            GuiInterfaceV1.reportError("Failed to parse " + file + "!");
//        } catch (CMSException e) {
//            GuiInterfaceV1.reportError("Failed to decode CMS data from " + file + "!");
//        } catch (CertificateException e ) { //| OperatorCreationException e) {
//            GuiInterfaceV1.reportError("Failed to extract certificate from CMS data!");
//        }
//        return false;
    }

    @Override
    public boolean canSign(String keypair_name) {
        X509Certificate cert = getCertificate(keypair_name);
        if (cert == null)
            return false;
        boolean[] keyUsageVector = cert.getKeyUsage(); // keyUsageVector[5] - keyCertSign
        return keyUsageVector != null && keyUsageVector[5] || cert.getBasicConstraints() != -1;
    }

    @Override
    public String getSubjectInfo(String keypair_name) {
        X509Certificate cert = getCertificate(keypair_name);
        if (cert == null)
            return null;
        return cert.getSubjectX500Principal().getName();
    }

    @Override
    public String getCertPublicKeyAlgorithm(String keypair_name) {
        X509Certificate cert = getCertificate(keypair_name);
        if (cert == null)
            return null;
        return cert.getPublicKey().getAlgorithm();
    }

    @Override
    public String getCertPublicKeyParameter(String keypair_name) {
        X509Certificate cert = getCertificate(keypair_name);
        if (cert == null)
            return null;
        String algorithm = cert.getPublicKey().getAlgorithm();
        switch (algorithm) {
            case "DSA":
                return Integer.toString(((DSAPublicKey) cert.getPublicKey()).getParams().getP().bitLength());
            case "RSA":
                return Integer.toString(((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength());
            case "EC":
                return ((ECPublicKey) cert.getPublicKey()).getParams().getCurve().toString();
            default:
                return null;
        }
    }
}