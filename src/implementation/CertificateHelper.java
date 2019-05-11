package implementation;

import gui.GuiInterfaceV1;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import x509.v3.GuiV3;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificateHelper {

    public static void addBouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static boolean assertKeyPairParams(GuiV3 access) {
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
        return true;
    }

    public static KeyPairGenerator initGenerator(int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                Project.PUBLIC_KEY_ALGORITHM,
                BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom random = SecureRandom.getInstance(
                Project.SECURE_RANDOM_ALGORITHM,
                Project.SECURE_RANDOM_PROVIDER);
        generator.initialize(keySize, random);
        return generator;
    }

    public static KeyPair generateKeyPair(int keySize)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = initGenerator(keySize);
        return generator.generateKeyPair();
    }

    public static X509Certificate generateSelfSignedCertificate(GuiV3 access, KeyPair pair)
            throws OperatorCreationException, CertificateException {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(access.getSubject()),
                new BigInteger(access.getSerialNumber()),
                access.getNotBefore(),
                access.getNotAfter(),
                new X500Name(access.getSubject()),
                pair.getPublic()
        );
        // TODO: add extensions...
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                builder.build(new JcaContentSignerBuilder(Project.DIGEST_ALGORITHM).setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).build(pair.getPrivate())));
    }

    // TODO: possibly modify to use IssuerDN, SubjectDN, IssuerKeyPair, SubjectKeyPair...
    public static X509Certificate generateCASignedCertificate(GuiV3 access, KeyPair pair)
            throws OperatorCreationException, CertificateException {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(access.getIssuer()),
                new BigInteger(access.getSerialNumber()),
                access.getNotBefore(),
                access.getNotAfter(),
                new X500Name(access.getSubject()),
                pair.getPublic()
        );
        // TODO: add extensions...
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                builder.build(new JcaContentSignerBuilder(Project.DIGEST_ALGORITHM).setProvider(
                        BouncyCastleProvider.PROVIDER_NAME).build(pair.getPrivate())));
    }
}