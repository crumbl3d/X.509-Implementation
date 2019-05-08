package implementation;

import code.GuiException;
import x509.v3.CodeV3;

import java.util.Enumeration;

public class MyCode extends CodeV3 {

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        return null;
    }

    @Override
    public void resetLocalKeystore() {

    }

    @Override
    public int loadKeypair(String s) {
        return 0;
    }

    @Override
    public boolean saveKeypair(String s) {
        return false;
    }

    @Override
    public boolean removeKeypair(String s) {
        return false;
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean exportKeypair(String s, String s1, String s2) {
        return false;
    }

    @Override
    public boolean importCertificate(String s, String s1) {
        return false;
    }

    @Override
    public boolean exportCertificate(String s, String s1, int i, int i1) {
        return false;
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
    public boolean canSign(String s) {
        return false;
    }

    @Override
    public String getSubjectInfo(String s) {
        return null;
    }

    @Override
    public String getCertPublicKeyAlgorithm(String s) {
        return null;
    }

    @Override
    public String getCertPublicKeyParameter(String s) {
        return null;
    }
}