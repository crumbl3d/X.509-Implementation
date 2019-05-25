package implementation;

import gui.Constants;

class Project {
    static final int CERTIFICATE_VERSION = Constants.V3;

    static final String PUBLIC_KEY_ALGORITHM = "DSA";
    static final String[] PUBLIC_KEY_SIZES = {"1024", "2048"};

    static final String DIGEST_ALGORITHM = "SHA1withDSA";

    static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    static final String SECURE_RANDOM_PROVIDER = "SUN";

    static final String KEYSTORE_TYPE = "PKCS12";
    static final String KEYSTORE_FILENAME = "keystore.p12";
    static final char[] KEYSTORE_PASSWORD = "uH8BxSzGLe6VJkg4cCV58SwRuAfNjRJ5".toCharArray();
    static final char[] KEY_PASSWORD = KEYSTORE_PASSWORD; // not really important in this example project...
}