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
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.*;

@SuppressWarnings("unused")
public class MyCode extends CodeV3 {

    static {
        Security.addProvider(new BouncyCastleProvider()); // add BouncyCastle provider
    }

    private KeyStore keystore;

    private final boolean supportsDSA;
    private final boolean supportsRSA;
    private final boolean supportsEC;

    private JcaPKCS10CertificationRequest lastCSR; // last sent request

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
        supportsDSA = algorithm_conf[0];
        supportsRSA = algorithm_conf[1];
        supportsEC = algorithm_conf[3];
        lastCSR = null;
    }

    //region Helpers

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

    private Certificate[] getCertificateChain(String keypair_name) {
        Certificate[] chain;
        try {
            chain = keystore.getCertificateChain(keypair_name);
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError("Failed to load certificate chain with alias: " + keypair_name + "!");
            return null;
        }
        if (chain == null)
            GuiInterfaceV1.reportError("Local keystore does not contain a certificate chain with the following alias: " + keypair_name);
        return chain;
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

    private Certificate[] establishCertChain(Certificate userCert, Certificate certToVerify) {
        if (userCert != null) {
            PublicKey origPU = userCert.getPublicKey();
            PublicKey replyPU = certToVerify.getPublicKey();
            if (!origPU.equals(replyPU)) {
                GuiInterfaceV1.reportError("CA reply does not a public key of selected keypair!");
                return null;
            }
            if (certToVerify.equals(userCert)) {
                GuiInterfaceV1.reportError("CA reply certificate is identical to selected certificate!");
                return null;
            }
        }

        Hashtable<Principal, Vector<Certificate>> certs = null;
        try {
            if (keystore.size() > 0) {
                certs = new Hashtable<>(11);
                generateCertHashtable(keystore, certs);
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        Vector<Certificate> chain = new Vector<>(2);
        if (buildChain((X509Certificate) certToVerify, chain, certs)) {
            Certificate[] newChain = new Certificate[chain.size()];
            int j = 0;
            for (int i = chain.size() - 1; i >= 0; i--) {
                newChain[j] = chain.elementAt(i);
                j++;
            }
            return newChain;
        }
        return null;
    }

    private Certificate[] validateReply(String keypair_name, Certificate userCert, Certificate[] replyCerts) {
        int i;
        PublicKey userPU = userCert.getPublicKey();

        HashSet<Certificate> nodup = new HashSet<>(Arrays.asList(replyCerts));
        replyCerts = nodup.toArray(new Certificate[0]); // remove duplicate certificates

        for (i = 0; i < replyCerts.length; i++) {
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

        for (i = 1; i < replyCerts.length - 1; i++) {
            int j;
            for (j = i; j < replyCerts.length; j++) {
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

        return replyCerts;
    }

    private void generateCertHashtable(KeyStore ks, Hashtable<Principal, Vector<Certificate>> hash) {
        try {
            for (Enumeration<String> aliases = ks.aliases();
                 aliases.hasMoreElements(); ) {
                String alias = aliases.nextElement();
                Certificate cert = ks.getCertificate(alias);
                if (cert != null) {
                    Principal subjectDN = ((X509Certificate)cert).getSubjectDN();
                    Vector<Certificate> vec = hash.get(subjectDN);
                    if (vec == null) {
                        vec = new Vector<>();
                        vec.addElement(cert);
                    } else {
                        if (!vec.contains(cert)) {
                            vec.addElement(cert);
                        }
                    }
                    hash.put(subjectDN, vec);
                }
            }
        } catch (KeyStoreException ignored) {}
    }

    private boolean buildChain(X509Certificate certToVerify, Vector<Certificate> chain, Hashtable<Principal, Vector<Certificate>> certs) {
        Principal issuer = certToVerify.getIssuerDN();
        if (CertificateHelper.selfSigned(certToVerify)) {
            chain.addElement(certToVerify);
            return true;
        }
        Vector<Certificate> vec = certs.get(issuer);
        if (vec == null) {
            return false;
        }
        for (Enumeration<Certificate> issuerCerts = vec.elements(); issuerCerts.hasMoreElements(); ) {
            X509Certificate issuerCert = (X509Certificate) issuerCerts.nextElement();
            PublicKey issuerPubKey = issuerCert.getPublicKey();
            try {
                certToVerify.verify(issuerPubKey);
            } catch (Exception e) {
                continue;
            }
            if (buildChain(issuerCert, chain, certs)) {
                chain.addElement(certToVerify);
                return true;
            }
        }
        return false;
    }

    private boolean addAuthorityKeyIdentifier(X509v3CertificateBuilder certBuilder, PublicKey issuerPU,
                                              String issuerDN, BigInteger issuerSerialNumber) {
        if (access.getEnabledAuthorityKeyID()) {
            if (access.isCritical(Constants.AKID)) {
                GuiInterfaceV1.reportError("Authority Key Identifier MUST NOT be marked critical!");
                return false;
            }
            try {
                certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                        new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(
                                issuerPU, new X500Principal(issuerDN), issuerSerialNumber));
            } catch (NoSuchAlgorithmException | CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add authority key identifier!");
                return false;
            }
        }
        return true;
    }

    private boolean addAuthorityKeyIdentifier(X509v3CertificateBuilder certBuilder, X509Certificate issuer) {
        if (access.getEnabledAuthorityKeyID()) {
            if (access.isCritical(Constants.AKID)) {
                GuiInterfaceV1.reportError("Authority Key Identifier MUST NOT be marked critical!");
                return false;
            }
            try {
                certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                        new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuer));
            } catch (NoSuchAlgorithmException | CertificateEncodingException | CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add authority key identifier!");
                return false;
            }
        }
        return true;
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean addIssuerAlternativeName(X509v3CertificateBuilder certBuilder) {
        if (access.getAlternativeName(Constants.IAN).length > 0) {
            if (access.isCritical(Constants.IAN)) {
                GuiInterfaceV1.reportError("Issuer Alternative Name SHOULD NOT be marked critical!");
            }
            try {
                String[] ian_arr = access.getAlternativeName(Constants.IAN);
                GeneralNamesBuilder namesBuilder = new GeneralNamesBuilder();
                for (String ian : ian_arr) {
                    String[] tokens = ian.split(":");
                    if (tokens.length < 2) {
                        GuiInterfaceV1.reportError("Invalid issuer alternative name: " + ian);
                        return false;
                    }
                    String type = tokens[0], value = ian.substring(type.length() + 1);
                    try {
                        switch (type.toLowerCase()) {
                            case "other":
                                namesBuilder.addName(new GeneralName(GeneralName.otherName, value));
                                break;
                            case "email":
                                namesBuilder.addName(new GeneralName(GeneralName.rfc822Name, value));
                                break;
                            case "dns":
                                namesBuilder.addName(new GeneralName(GeneralName.dNSName, value));
                                break;
                            case "x400address":
                                namesBuilder.addName(new GeneralName(GeneralName.x400Address, value));
                                break;
                            case "dn":
                                namesBuilder.addName(new GeneralName(GeneralName.directoryName, value.replace(';', ',')));
                                break;
                            case "edipartyname":
                                namesBuilder.addName(new GeneralName(GeneralName.ediPartyName, value));
                                break;
                            case "uri":
                                namesBuilder.addName(new GeneralName(GeneralName.uniformResourceIdentifier, value));
                                break;
                            case "ip":
                                namesBuilder.addName(new GeneralName(GeneralName.iPAddress, value));
                                break;
                            case "rid":
                                namesBuilder.addName(new GeneralName(GeneralName.registeredID, value));
                                break;
                            default:
                                GuiInterfaceV1.reportError("Invalid issuer alternative name type: " + type);
                                return false;
                        }
                    } catch (IllegalArgumentException e) {
                        GuiInterfaceV1.reportError("Invalid issuer alternative name value: " + value + " for type: " + type);
                        return false;
                    }
                }
                certBuilder.addExtension(Extension.issuerAlternativeName,
                        access.isCritical(Constants.IAN), namesBuilder.build());
            } catch (CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add issuer alternative name!");
                return false;
            }
        }
        return true;
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean addExtendedKeyUsage(X509v3CertificateBuilder certBuilder) {
        boolean extendedKeyUsage = false;
        for (boolean flag : access.getExtendedKeyUsage())
            if (flag) {
                extendedKeyUsage = true;
                break;
            }
        if (extendedKeyUsage) {
            try {
                boolean[] guiUsageVector = access.getExtendedKeyUsage();
                boolean isCritical = access.isCritical(Constants.EKU);
                ArrayList<KeyPurposeId> usage = new ArrayList<>();
                if (guiUsageVector[0]) {
                    usage.add(KeyPurposeId.anyExtendedKeyUsage);
                    // If the anyExtendedKeyUsage keyPurposeID is present, the extension SHOULD NOT be critical.
                    // ref: https://tools.ietf.org/html/rfc3280 @4.2.1.13
                    isCritical = false;
                } else {
                    if (guiUsageVector[1])
                        usage.add(KeyPurposeId.id_kp_serverAuth);
                    if (guiUsageVector[2])
                        usage.add(KeyPurposeId.id_kp_clientAuth);
                    if (guiUsageVector[3])
                        usage.add(KeyPurposeId.id_kp_codeSigning);
                    if (guiUsageVector[4])
                        usage.add(KeyPurposeId.id_kp_emailProtection);
                    if (guiUsageVector[5])
                        usage.add(KeyPurposeId.id_kp_timeStamping);
                    if (guiUsageVector[6])
                        usage.add(KeyPurposeId.id_kp_OCSPSigning);
                }
                certBuilder.addExtension(Extension.extendedKeyUsage, isCritical,
                        new ExtendedKeyUsage(usage.toArray(new KeyPurposeId[0])));
            } catch (CertIOException e) {
                GuiInterfaceV1.reportError("Failed to add extended key usage!");
                return false;
            }
        }
        return true;
    }

    private static boolean[] getGuiUsageVector(ExtendedKeyUsage eku) {
        boolean[] guiUsageVector = new boolean[7];
        guiUsageVector[0] = eku.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage);
        guiUsageVector[1] = eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth);
        guiUsageVector[2] = eku.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth);
        guiUsageVector[3] = eku.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning);
        guiUsageVector[4] = eku.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection);
        guiUsageVector[5] = eku.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping);
        guiUsageVector[6] = eku.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning);
        return guiUsageVector;
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

    //endregion

    //region Local keystore management

    @Override
    public Enumeration<String> loadLocalKeystore() {
        try {
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

    private boolean saveLocalKeystore(boolean report) {
        try (FileOutputStream output = new FileOutputStream(Project.KEYSTORE_FILENAME)) {
            keystore.store(output, Project.KEYSTORE_PASSWORD);
            return true;
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to open " + Project.KEYSTORE_FILENAME + "!");
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            GuiInterfaceV1.reportError("Failed to save the local keystore to: " + Project.KEYSTORE_FILENAME + "!");
        }
        return false;
    }

    private void saveLocalKeystore() {
        saveLocalKeystore(true);
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

    //endregion

    //region Keypair generation, loading and removal

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
            access.setPublicKeyParameter(CertificateHelper.getPublicKeyParameter(cert)); // Public key parameter
            access.setPublicKeyDigestAlgorithm(CertificateHelper.getSignatureAlgorithm(cert)); // Signature algorithm
        }

        // --- Subject panel ---
        access.setSubject(CertificateHelper.getSubjectInfo(cert)); // Subject info
        access.setSubjectSignatureAlgorithm(CertificateHelper.getPublicKeyAlgorithm(cert)); // Public key algorithm

        // --- Issuer panel ---
        access.setIssuer(CertificateHelper.getIssuerInfo(cert)); // Issuer info
        access.setIssuerSignatureAlgorithm(CertificateHelper.getSignatureAlgorithm(cert)); // Signature algorithm

        // --- Extensions panel ---
        X509CertificateHolder holder;
        try {
            holder = new JcaX509CertificateHolder(cert);
        } catch (CertificateEncodingException e) {
            return -1;
        }

        Extensions extensions = holder.getExtensions();

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
            StringBuilder sb = new StringBuilder();
            try {
                Iterator it = cert.getIssuerAlternativeNames().iterator();
                while (it.hasNext()) {
                    List list = (List) it.next();
                    int type = (int) list.get(0);
                    String value = (String) list.get(1);
                    switch (type) {
                        case GeneralName.otherName:
                            sb.append("Other");
                            break;
                        case GeneralName.rfc822Name:
                            sb.append("Email");
                            break;
                        case GeneralName.dNSName:
                            sb.append("DNS");
                            break;
                        case GeneralName.x400Address:
                            sb.append("x400Address");
                            break;
                        case GeneralName.directoryName:
                            sb.append("DN");
                            break;
                        case GeneralName.ediPartyName:
                            sb.append("EDIPartyName");
                            break;
                        case GeneralName.uniformResourceIdentifier:
                            sb.append("URI");
                            break;
                        case GeneralName.iPAddress:
                            sb.append("IP");
                            break;
                        case GeneralName.registeredID:
                            sb.append("RID");
                            break;
                        default:
                            GuiInterfaceV1.reportError("Invalid issuer alternative name: " + type + ":" + value);
                            return -1;
                    }
                    sb.append(":").append(value);
                    if (it.hasNext())
                        sb.append(",");
                }
            } catch (CertificateParsingException e) {
                GuiInterfaceV1.reportError("Failed to parse issuer alternative name!");
                return -1;
            }
            access.setAlternativeName(Constants.IAN, sb.toString());
        }

        // Extended key usage
        Extension extendedKeyUsage = extensions.getExtension(Extension.extendedKeyUsage);
        if (extendedKeyUsage != null) {
            access.setCritical(Constants.EKU, extendedKeyUsage.isCritical());
            access.setExtendedKeyUsage(getGuiUsageVector(ExtendedKeyUsage.fromExtensions(extensions)));
        }

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

        if (CertificateHelper.canSign(cert))
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
        boolean cond = false;
        for (String param : Project.PUBLIC_KEY_SIZES) {
            if (cond = param.equals(access.getPublicKeyParameter()))
                break;
        }
        if (!cond) {
            GuiInterfaceV1.reportError("Unsupported public key algorithm parameter: " + access.getPublicKeyParameter() + "!");
            return false;
        }
        if (!access.getPublicKeyDigestAlgorithm().equals(Project.DIGEST_ALGORITHM)) {
            GuiInterfaceV1.reportError("Unsupported public key digest algorithm: " + access.getPublicKeyDigestAlgorithm() + "!");
            return false;
        }

        KeyPair pair;
        try {
            pair = CertificateHelper.generateKeyPair(access.getPublicKeyAlgorithm(), Integer.parseInt(access.getPublicKeyParameter()));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            GuiInterfaceV1.reportError("Failed to generate a keypair with " + access.getPublicKeyAlgorithm() + "!");
            return false;
        }

        X509v3CertificateBuilder certBuilder = CertificateHelper.initCertificateBuilder(
                access.getSubject(), access.getSubject(), pair.getPublic(),
                new BigInteger(access.getSerialNumber()), access.getNotBefore(), access.getNotAfter());
        if (certBuilder == null) {
            GuiInterfaceV1.reportError("Failed to initialize certificate builder!");
            return false;
        }

        if (!addAuthorityKeyIdentifier(certBuilder, pair.getPublic(), access.getSubject(),
                new BigInteger(access.getSerialNumber()))
            || !addIssuerAlternativeName(certBuilder)
            || !addExtendedKeyUsage(certBuilder)) {
            GuiInterfaceV1.reportError("Failed to add certificate extensions!");
            return false;
        }

        X509Certificate cert;
        try {
            cert = CertificateHelper.generateSignedCertificate(
                    certBuilder, access.getPublicKeyDigestAlgorithm(), pair.getPrivate());
        } catch (OperatorCreationException | CertificateException e) {
            GuiInterfaceV1.reportError("Failed to generate certificate!");
            return false;
        }
        if (cert == null)
            return false;

        try {
            keystore.setKeyEntry(keypair_name, pair.getPrivate(), Project.KEY_PASSWORD, new Certificate[]{cert});
        } catch (KeyStoreException e) {
            GuiInterfaceV1.reportError("Failed to save generated keypair!");
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

    //endregion

    //region Keypair import/export

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

    //endregion

    //region Certificate import/export

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
                if (chain == null)
                    return false;
                if (encoding == 0) { // DER
                    OutputStream out = new FileOutputStream(file);
                    DEROutputStream dos = new DEROutputStream(out);
                    for (Certificate cert : chain) {
                        try (ASN1InputStream asn1 = new ASN1InputStream(cert.getEncoded())) {
                            dos.writeObject(asn1.readObject());
                        }
                    }
                    dos.flush();
                    dos.close();
                } else { // PEM
                    try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(new File(file)))) {
                        for (Certificate cert : chain) {
                            pemWriter.writeObject(new JcaMiscPEMGenerator(cert));
                        }
                        pemWriter.flush();
                    }
                }
            }
            return true;
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to open " + file + "!");
        } catch (Exception e) {
            GuiInterfaceV1.reportError("Failed to load keypair: " + keypair_name + "!");
        }
        return false;
    }

    //endregion

    //region Certificate signing

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
            GuiInterfaceV1.reportError("Failed to generate certificate signing request!");
            return false;
        }
        try {
            return writePEM(new FileWriter(new File(file)), request);
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to write certificate signing request to " + file + "!");
        }
        return false;
    }

    @Override
    public String importCSR(String file) {
        PKCS10CertificationRequest request;
        try {
            PEMParser parser = new PEMParser(new FileReader(new File(file)));
            request = (PKCS10CertificationRequest) parser.readObject();
        } catch (FileNotFoundException e) {
            GuiInterfaceV1.reportError("Failed to open " + file + "!");
            return null;
        } catch (IOException e) {
            GuiInterfaceV1.reportError("Failed to parse " + file + "!");
            return null;
        }
        if (request == null)
            return null;
        this.lastCSR = new JcaPKCS10CertificationRequest(request);
        return request.getSubject().toString();
    }

    @Override
    public boolean signCSR(String file, String keypair_name, String algorithm) {
        if (lastCSR == null)
            return false; // csr not initialized

        Certificate[] caChain = getCertificateChain(keypair_name);
        if (caChain == null || caChain.length <= 0)
            return false; // invalid ca chain

        X509Certificate ca = (X509Certificate) caChain[0];
        if (ca == null)
            return false;

        try {
            ca.checkValidity(); // checking if the ca has expired
        } catch (CertificateExpiredException e) {
            GuiInterfaceV1.reportError("CA certificate: " + keypair_name + " has expired and cannot be used to sign a CSR!");
            return false;
        } catch (CertificateNotYetValidException e) {
            GuiInterfaceV1.reportError("CA certificate: " + keypair_name + " is not yet valid and cannot be used to sign a CSR!");
            return false;
        }

        PrivateKey caPK = getPrivateKey(keypair_name);
        if (caPK == null)
            return false; // failed to get ca private key

        X509v3CertificateBuilder certBuilder;
        try {
             certBuilder = CertificateHelper.initCertificateBuilder(
                    access.getIssuer(), access.getSubject(),
                    lastCSR.getPublicKey(), new BigInteger(access.getSerialNumber()),
                    access.getNotBefore(), access.getNotAfter());
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            return false;
        }
        if (certBuilder == null) {
            GuiInterfaceV1.reportError("Failed to initialize certificate builder!");
            return false;
        }

        if (!addAuthorityKeyIdentifier(certBuilder, ca)
            || !addIssuerAlternativeName(certBuilder)
            || !addExtendedKeyUsage(certBuilder)) {
            GuiInterfaceV1.reportError("Failed to add certificate extensions!");
            return false;
        }

        X509Certificate cert;
        try {
            cert = CertificateHelper.generateSignedCertificate(certBuilder, algorithm, caPK);
        } catch (OperatorCreationException | CertificateException e) {
            GuiInterfaceV1.reportError("Failed to generate signed certificate!");
            return false;
        }

        Store certStore;
        List<Certificate> chain = new ArrayList<>(Arrays.asList(caChain));

        try {
            certStore = new JcaCertStore(chain);
        } catch (CertificateEncodingException e) {
            return false; // failed to initialize cert store
        }

        CMSSignedDataGenerator cmsGen = new CMSSignedDataGenerator();

        ContentSigner signer;
        try {
            signer = new JcaContentSignerBuilder(algorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPK);
            cmsGen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build()).build(signer, ca));
            cmsGen.addCertificate(new JcaX509CertificateHolder(cert));
            cmsGen.addCertificates(certStore);
        } catch (OperatorCreationException | CMSException | CertificateEncodingException e) {
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
            // writeDER(new FileOutputStream(file), sigData.getEncoded());
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

        Certificate[] replyCerts = c.toArray(new Certificate[0]);
        Certificate[] newChain;

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
    }

    //endregion

    //region GUI helper methods

    @Override
    public boolean canSign(String keypair_name) {
        return CertificateHelper.canSign(getCertificate(keypair_name));
    }

    @Override
    public String getSubjectInfo(String keypair_name) {
        return CertificateHelper.getSubjectInfo(getCertificate(keypair_name));
    }

    @Override
    public String getCertPublicKeyAlgorithm(String keypair_name) {
        return CertificateHelper.getPublicKeyAlgorithm(getCertificate(keypair_name));
    }

    @Override
    public String getCertPublicKeyParameter(String keypair_name) {
        return CertificateHelper.getPublicKeyParameter(getCertificate(keypair_name));
    }

    //endregion

}