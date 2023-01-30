import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class DSA {
    public static void main(String[] args) {
        BigInteger p = new BigInteger("50702342087986984684596540672785294493370824085308498450535565701730450879745310594069460940052367603038103747343106687981163754506284021184158903198888031001641800021787453760919626851704381009545624331468658731255109995186698602388616345118779571212089090418972317301933821327897539692633740906524461904910061687459642285855052275274576089050579224477511686171168825003847462222895619169935317974865296291598100558751976216418469984937110507061979400971905781410388336458908816885758419125375047408388601985300884500733923194700051030733653434466714943605845143519933901592158295809020513235827728686129856549511535000228593790299010401739984240789015389649972633253273119008010971111107028536093543116304613269438082468960788836139999390141570158208410234733780007345264440946888072018632119778442194822690635460883177965078378404035306423001560546174260935441728479454887884057082481520089810271912227350884752023760663");
        BigInteger q = new BigInteger("63762351364972653564641699529205510489263266834182771617563631363277932854227");

        //key generation
        KeyGen keyGen = new KeyGen(p, q);
        KeyPair keyPair = keyGen.init();

        System.out.println("----------------------------");
        System.out.println("Signing:");
        System.out.printf("DSA signing key x = %s\n", keyPair.getSigningKey().getX());
        System.out.printf("DSA verification key vk = (y, h, p, q) = %s\n", keyPair.getVerificationKey());

        //Signing
        System.out.println("----------------------------");
        System.out.println("Signing:");
        BigInteger m = new BigInteger(q.bitLength() - 1, new Random());
        System.out.printf("Message to be signed m = %s\n", m);
        Signature signature = getSignature(keyPair.getSigningKey(), keyPair.getVerificationKey(), m);
        System.out.printf("Signature = (r, s) = %s\n", signature);

        //verification
        System.out.println("----------------------------");
        System.out.println("Verification:");
        System.out.printf("Verification result: %s\n", verifySignature(keyPair.getVerificationKey(), m, signature) ? "SIGNATURE ACCEPTED" : "SIGNATURE REJECTED");

        System.out.println("----------------------------");
    }

    private static boolean verifySignature(VerificationKey verificationKey, BigInteger m, Signature signature) {
        BigInteger p = verificationKey.getP();
        BigInteger q = verificationKey.getQ();
        BigInteger y = verificationKey.getY();
        BigInteger h = verificationKey.getH();
        BigInteger s = signature.getS();
        BigInteger r = signature.getR();
        BigInteger w = s.modInverse(q);
        BigInteger u1 = w.multiply(sha256(m)).mod(q);
        BigInteger u2 = r.multiply(w).mod(q);
        BigInteger v = ((h.modPow(u1, p).multiply(y.modPow(u2, p))).mod(p)).mod(q);
        System.out.printf("Printing w = %s\n", w);
        System.out.printf("Printing u1 = %s\n", u1);
        System.out.printf("Printing u2 = %s\n", u2);
        System.out.printf("Printing v = %s\n", v);
        return v.compareTo(r) == 0;
    }

    private static Signature getSignature(SigningKey signingKey, VerificationKey verificationKey, BigInteger m) {
        BigInteger x = signingKey.getX();
        BigInteger p = verificationKey.getP();
        BigInteger q = verificationKey.getQ();
        BigInteger h = verificationKey.getH();
        BigInteger k = DSA.generateRandomK(q);
        BigInteger r = h.modPow(k, p).mod(q);
        BigInteger kDash = k.modInverse(q);
        BigInteger s = kDash.multiply(Utils.sha256(m).add(x.multiply(r)).mod(q));
        return new Signature(r, s);
    }

    public static BigInteger generateRandomK(BigInteger q) {
        BigInteger x = BigInteger.TWO;
        while (x.compareTo(BigInteger.TWO) <= 0 || x.compareTo(q.subtract(BigInteger.ONE)) > 0) {
            x = new BigInteger(q.subtract(BigInteger.ONE).bitLength(), new Random());
        }
        return x;
    }

    public static BigInteger sha256(BigInteger input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return new BigInteger(md.digest(input.toByteArray()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return BigInteger.ONE;
    }
}

class KeyGen {
    private final BigInteger p;
    private final BigInteger q;

    public KeyGen(BigInteger p, BigInteger q) {
        this.p = p;
        this.q = q;
    }

    public KeyPair init() {
        BigInteger g = BigInteger.TWO;
        BigInteger h = g.modPow(p.subtract(BigInteger.ONE).divide(q), p);
        BigInteger x = new BigInteger(this.q.bitLength() - 1, new Random());
        BigInteger y = h.modPow(x, p);
        return new KeyPair(new SigningKey(x), new VerificationKey(y, h, p, q));
    }
}

class KeyPair {
    private final SigningKey signingKey;
    private final VerificationKey verificationKey;

    public KeyPair(SigningKey signingKey, VerificationKey verificationKey) {
        this.signingKey = signingKey;
        this.verificationKey = verificationKey;
    }

    public SigningKey getSigningKey() {
        return signingKey;
    }

    public VerificationKey getVerificationKey() {
        return verificationKey;
    }
}

class Signature {
    private final BigInteger s;
    private final BigInteger r;

    public Signature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public BigInteger getS() {
        return s;
    }

    public BigInteger getR() {
        return r;
    }

    @Override
    public String toString() {
        return String.format("(%s, %s)", getR(), getS());
    }
}

class SigningKey {
    private final BigInteger x;

    public SigningKey(BigInteger x) {
        this.x = x;
    }

    public BigInteger getX() {
        return x;
    }

    @Override
    public String toString() {
        return String.format("(%s)", x);
    }
}

class VerificationKey {
    private final BigInteger y;
    private final BigInteger h;
    private final BigInteger p;
    private final BigInteger q;

    public VerificationKey(BigInteger y, BigInteger h, BigInteger p, BigInteger q) {
        this.y = y;
        this.h = h;
        this.p = p;
        this.q = q;
    }

    public BigInteger getY() {
        return y;
    }

    public BigInteger getH() {
        return h;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    @Override
    public String toString() {
        return String.format("(%s, %s, %s, %s)", getY(), getH(), getP(), getQ());
    }
}