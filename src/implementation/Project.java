package implementation;

import gui.Constants;

public class Project {
    public static final int CERTIFICATE_VERSION = Constants.V3;

    public static final String PUBLIC_KEY_ALGORITHM = "DSA";
    public static final String[] PUBLIC_KEY_SIZES = {"1024", "2048"};

    public static final String DIGEST_ALGORITHM = "SHA1withDSA";

    public static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    public static final String SECURE_RANDOM_PROVIDER = "SUN";

    public static final String KEYSTORE_TYPE = "PKCS12";
    public static final String KEYSTORE_FILENAME = "keystore.p12";
    public static final char[] KEYSTORE_PASSWORD = "uH8BxSzGLe6VJkg4cCV58SwRuAfNjRJ5".toCharArray();
    public static final char[] KEY_PASSWORD = KEYSTORE_PASSWORD; // not really important in this example project...
}