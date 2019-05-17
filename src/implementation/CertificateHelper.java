package implementation;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

class CertificateHelper {

    private static Map<String, String> algorithms = new HashMap<>();

    static {
        // Initializing algorithm OID to name map
        algorithms.put(X9ObjectIdentifiers.id_dsa.getId(), "DSA");
        algorithms.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "SHA1withDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA1.getId(), "SHA1withECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), "SHA256withECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA384.getId(), "SHA384withECDSA");
        algorithms.put(X9ObjectIdentifiers.ecdsa_with_SHA512.getId(), "SHA512withECDSA");
        algorithms.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1withRSA");
        algorithms.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256withRSA");
        algorithms.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384withRSA");
        algorithms.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512withRSA");
    }

    static String getSignatureAlgorithm(X509Certificate cert) {
        if (algorithms.containsKey(cert.getSigAlgOID()))
            return algorithms.get(cert.getSigAlgOID());
        return cert.getSigAlgName();
    }

    static boolean[] getGuiUsageVector(ExtendedKeyUsage eku) {
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

    static KeyPair generateKeyPair(String algorithm, int keySize)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                algorithm,
                BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom random = SecureRandom.getInstance(
                Project.SECURE_RANDOM_ALGORITHM,
                Project.SECURE_RANDOM_PROVIDER);
        generator.initialize(keySize, random);
        return generator.generateKeyPair();
    }

    static X509v3CertificateBuilder initCertificateBuilder(
            String issuerDN, String subjectDN, PublicKey subjectPublicKey,
            BigInteger serialNumber, Date notBefore, Date notAfter) {
        if (issuerDN == null || issuerDN.isEmpty() || subjectDN == null || subjectDN.isEmpty() ||
                subjectPublicKey == null || serialNumber == null || notBefore == null || notAfter == null)
            return null;
        return new JcaX509v3CertificateBuilder(
                new X500Name(issuerDN), // Issuer descriptor name
                serialNumber,
                notBefore,
                notAfter,
                new X500Name(subjectDN),
                subjectPublicKey
        );
    }

    static void addAuthorityKeyIdentifier(
            X509v3CertificateBuilder certBuilder, boolean isCritical, X509Certificate issuerCert)
            throws NoSuchAlgorithmException, CertificateEncodingException, CertIOException {
        certBuilder.addExtension(Extension.authorityKeyIdentifier, isCritical,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerCert));
    }

    static void addAuthorityKeyIdentifier(
            X509v3CertificateBuilder certBuilder, boolean isCritical, PublicKey issuerPublicKey,
            String issuerDN, BigInteger issuerSerialNumber)
            throws NoSuchAlgorithmException, CertIOException {
        certBuilder.addExtension(Extension.authorityKeyIdentifier, isCritical,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(
                        issuerPublicKey, new X500Principal(issuerDN), issuerSerialNumber));
    }

    static void addIssuerAlternativeName(
            X509v3CertificateBuilder certBuilder, boolean isCritical, String[] names) throws CertIOException {
        GeneralNamesBuilder namesBuilder = new GeneralNamesBuilder();
        for (String name : names)
            // TODO: All names are processed as other, since there is no easy way to check the name's format
            namesBuilder.addName(new GeneralName(GeneralName.otherName, name));
        certBuilder.addExtension(Extension.issuerAlternativeName, isCritical, namesBuilder.build());
    }

    static void addExtendedKeyUsage(
            X509v3CertificateBuilder certBuilder, boolean isCritical, boolean[] guiUsageVector)
            throws CertIOException {
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
    }

    static X509Certificate generateSignedCertificate(
            X509v3CertificateBuilder certBuilder, String signatureAlgorithm, PrivateKey issuerPrivateKey)
            throws OperatorCreationException, CertificateException {
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                certBuilder.build(new JcaContentSignerBuilder(signatureAlgorithm).setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).build(issuerPrivateKey)));
    }

    @SuppressWarnings("SameParameterValue")
    static PKCS10CertificationRequest generateCSR(X509Certificate cert, PrivateKey privateKey, String algorithm)
            throws CertificateEncodingException, OperatorCreationException {
        X509CertificateHolder holder = new JcaX509CertificateHolder(cert);
        ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(privateKey);
        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(cert.getSubjectX500Principal(), cert.getPublicKey());
        if (holder.getExtensions() != null)
            requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, holder.getExtensions());
        return requestBuilder.build(signer);
    }

    @SuppressWarnings("unused")
    static Extensions getExtensionsFromCSR(PKCS10CertificationRequest csr) {
        for (Attribute attribute : csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
            ASN1Set attValue = attribute.getAttrValues();
            if (attValue != null) {
                ASN1Encodable extension = attValue.getObjectAt(0);
                if (extension instanceof Extensions) {
                    return (Extensions) extension;
                } else if (extension instanceof DERSequence) {
                    return Extensions.getInstance(extension);
                }
            }
        }
        return null;
    }

    static boolean selfSigned(X509Certificate cert) {
        return signedBy(cert, cert);
    }

    static boolean signedBy(X509Certificate end, X509Certificate ca) {
        if (!ca.getSubjectDN().equals(end.getIssuerDN())) {
            return false;
        }
        try {
            end.verify(ca.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            return false;
        }
    }

//    private X509Certificate generateSignedCertificate(X509Certificate rootCert,
//                                                      PKCS10CertificationRequest csr) throws NoSuchAlgorithmException,
//            NoSuchProviderException, InvalidKeyException,
//            CertificateParsingException, CertificateEncodingException,
//            SignatureException {
//
//        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
//        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
//        certGen.setIssuerDN(rootCert.getSubjectX500Principal());
//        Calendar c = Calendar.getInstance();
//        certGen.setNotBefore(c.getTime());
//        c.add(Calendar.YEAR, 1);
//        certGen.setNotAfter(c.getTime());
//        certGen.setSubjectDN(csr.getCertificationRequestInfo().getSubject());
//        certGen.setPublicKey(csr.getPublicKey("BC"));
//        certGen.setSignatureAlgorithm(ALGORITHM_SHA256_RSA);
//        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
//                new AuthorityKeyIdentifierStructure(rootCert.getPublicKey()));
//        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
//                new SubjectKeyIdentifierStructure(csr.getPublicKey("BC")));
//        certGen.addExtension(X509Extensions.BasicConstraints, true,
//                new BasicConstraints(false));
//        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(
//                KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
//
//        X509Certificate issuedCert = certGen.generate(rootPrivateKeyEntry
//                .getPrivateKey());
//        return issuedCert;
//    }

//    public static X509Certificate generateSelfSignedCertificate(GuiV3 access, KeyPair pair)
//            throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {
//        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
//                new X500Name(access.getSubject()),
//                new BigInteger(access.getSerialNumber()),
//                access.getNotBefore(),
//                access.getNotAfter(),
//                new X500Name(access.getSubject()),
//                pair.getPublic()
//        );
//        if (access.getEnabledAuthorityKeyID()) {
//            certBuilder.addExtension(Extension.authorityKeyIdentifier, access.isCritical(Constants.AKID),
//                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(pair.getPublic())); // issuer public key
//        }
//        if (access.getAlternativeName(Constants.IAN).length > 0) {
//            GeneralNamesBuilder namesBuilder = new GeneralNamesBuilder();
//            for (String name : access.getAlternativeName(Constants.IAN)) {
//                new GeneralName(new X500Name(name));
//            }
//            certBuilder.addExtension(Extension.issuerAlternativeName, access.isCritical(Constants.IAN), namesBuilder.build());
//        }
//        if (access.getExtendedKeyUsage() != null) {
//            boolean[] usage = access.getExtendedKeyUsage();
//            ASN1EncodableVector purposes = new ASN1EncodableVector();
//            if (usage[0])
//                purposes.add(KeyPurposeId.anyExtendedKeyUsage);
//            else {
//                if (usage[1])
//                    purposes.add(KeyPurposeId.id_kp_serverAuth);
//                if (usage[2])
//                    purposes.add(KeyPurposeId.id_kp_clientAuth);
//                if (usage[3])
//                    purposes.add(KeyPurposeId.id_kp_codeSigning);
//                if (usage[4])
//                    purposes.add(KeyPurposeId.id_kp_emailProtection);
//                if (usage[5])
//                    purposes.add(KeyPurposeId.id_kp_timeStamping);
//                if (usage[6])
//                    purposes.add(KeyPurposeId.id_kp_OCSPSigning);
//            }
//            certBuilder.addExtension(Extension.extendedKeyUsage, access.isCritical(Constants.EKU), new DERSequence(purposes));
//        }
//        // TODO: add extensions...
//        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
//                certBuilder.build(new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm()).setProvider(
//                        BouncyCastleProvider.PROVIDER_NAME).build(pair.getPrivate())));
//    }
//
//    // TODO: possibly modify to use IssuerDN, SubjectDN, IssuerKeyPair, SubjectKeyPair...
//    public static X509Certificate generateCASignedCertificate(GuiV3 access, KeyPair pair)
//            throws OperatorCreationException, CertificateException {
//        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
//                new X500Name(access.getIssuer()),
//                new BigInteger(access.getSerialNumber()),
//                access.getNotBefore(),
//                access.getNotAfter(),
//                new X500Name(access.getSubject()),
//                pair.getPublic()
//        );
//        // TODO: add extensions...
//        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
//                builder.build(new JcaContentSignerBuilder(Project.DIGEST_ALGORITHM).setProvider(
//                        BouncyCastleProvider.PROVIDER_NAME).build(pair.getPrivate())));
//    }
}