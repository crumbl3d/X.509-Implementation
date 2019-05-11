package implementation;

import gui.Constants;
import gui.GuiInterfaceV1;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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

    public static KeyPairGenerator initGenerator(String algorithm, int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                algorithm,
                BouncyCastleProvider.PROVIDER_NAME);
        SecureRandom random = SecureRandom.getInstance(
                Project.SECURE_RANDOM_ALGORITHM,
                Project.SECURE_RANDOM_PROVIDER);
        generator.initialize(keySize, random);
        return generator;
    }

    public static KeyPair generateKeyPair(String algorithm, int keySize)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator generator = initGenerator(algorithm, keySize);
        return generator.generateKeyPair();
    }

    public static X509Certificate generateSelfSignedCertificate(GuiV3 access, KeyPair pair)
            throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name(access.getSubject()),
                new BigInteger(access.getSerialNumber()),
                access.getNotBefore(),
                access.getNotAfter(),
                new X500Name(access.getSubject()),
                pair.getPublic()
        );
        if (access.getEnabledAuthorityKeyID()) {
            certBuilder.addExtension(Extension.authorityKeyIdentifier, access.isCritical(Constants.AKID),
                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(pair.getPublic())); // issuer public key
        }
        if (access.getAlternativeName(Constants.IAN).length > 0) {
            GeneralNamesBuilder namesBuilder = new GeneralNamesBuilder();
            for (String name : access.getAlternativeName(Constants.IAN)) {
                new GeneralName(new X500Name(name));
            }
            certBuilder.addExtension(Extension.issuerAlternativeName, access.isCritical(Constants.IAN), namesBuilder.build());
        }
        if (access.getExtendedKeyUsage() != null) {
            boolean[] usage = access.getExtendedKeyUsage();
            ASN1EncodableVector purposes = new ASN1EncodableVector();
            if (usage[0])
                purposes.add(KeyPurposeId.anyExtendedKeyUsage);
            else {
                if (usage[1])
                    purposes.add(KeyPurposeId.id_kp_serverAuth);
                if (usage[2])
                    purposes.add(KeyPurposeId.id_kp_clientAuth);
                if (usage[3])
                    purposes.add(KeyPurposeId.id_kp_codeSigning);
                if (usage[4])
                    purposes.add(KeyPurposeId.id_kp_emailProtection);
                if (usage[5])
                    purposes.add(KeyPurposeId.id_kp_timeStamping);
                if (usage[6])
                    purposes.add(KeyPurposeId.id_kp_OCSPSigning);
            }
            certBuilder.addExtension(Extension.extendedKeyUsage, access.isCritical(Constants.EKU), new DERSequence(purposes));
        }
        // TODO: add extensions...
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                certBuilder.build(new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm()).setProvider(
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