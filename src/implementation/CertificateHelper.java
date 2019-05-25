package implementation;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

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

    static String getSubjectInfo(X509Certificate cert) {
        if (cert == null)
            return null;
        return cert.getSubjectX500Principal().getName();
    }

    static String getIssuerInfo(X509Certificate cert) {
        if (cert == null)
            return null;
        return cert.getIssuerX500Principal().getName();
    }

    static String getPublicKeyAlgorithm(X509Certificate cert) {
        if (cert == null)
            return null;
        return cert.getPublicKey().getAlgorithm();
    }

    static String getPublicKeyParameter(X509Certificate cert) {
        String algorithm = CertificateHelper.getPublicKeyAlgorithm(cert);
        if (algorithm == null)
            return null;
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

    static String getSignatureAlgorithm(X509Certificate cert) {
        if (cert == null)
            return null;
        if (algorithms.containsKey(cert.getSigAlgOID()))
            return algorithms.get(cert.getSigAlgOID());
        return cert.getSigAlgName();
    }

    static boolean signedBy(X509Certificate end, X509Certificate ca) {
        if (end == null || ca == null)
            return false;
        if (!ca.getSubjectDN().equals(end.getIssuerDN()))
            return false;
        try {
            end.verify(ca.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException |
                SignatureException | NoSuchProviderException e) {
            return false;
        }
    }

    static boolean selfSigned(X509Certificate cert) {
        if (cert == null)
            return false;
        return signedBy(cert, cert);
    }

    static boolean canSign(X509Certificate cert) {
        if (cert == null)
            return false;
        boolean[] keyUsageVector = cert.getKeyUsage(); // keyUsageVector[5] = keyCertSign
        return keyUsageVector != null && keyUsageVector[5] || cert.getBasicConstraints() != -1;
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

}