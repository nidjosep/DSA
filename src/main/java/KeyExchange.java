import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class KeyExchange {

    public static void main(String[] args) {
        BigInteger p = new BigInteger("50702342087986984684596540672785294493370824085308498450535565701730450879745310594069460940052367603038103747343106687981163754506284021184158903198888031001641800021787453760919626851704381009545624331468658731255109995186698602388616345118779571212089090418972317301933821327897539692633740906524461904910061687459642285855052275274576089050579224477511686171168825003847462222895619169935317974865296291598100558751976216418469984937110507061979400971905781410388336458908816885758419125375047408388601985300884500733923194700051030733653434466714943605845143519933901592158295809020513235827728686129856549511535000228593790299010401739984240789015389649972633253273119008010971111107028536093543116304613269438082468960788836139999390141570158208410234733780007345264440946888072018632119778442194822690635460883177965078378404035306423001560546174260935441728479454887884057082481520089810271912227350884752023760663");
        BigInteger q = new BigInteger("63762351364972653564641699529205510489263266834182771617563631363277932854227");
        BigInteger g = BigInteger.TWO;

        Alice alice = Alice.initKeyGen(g, p, q);
        System.out.println("----------------------------");
        System.out.printf("DH private key for Alice x: %s\n", alice.getPrivateKey());
        Bob bob = Bob.initKeyGen(g, p, q);
        alice.setVerificationKey(bob.getVerificationKey());
        bob.setVerificationKey(alice.getVerificationKey());

        alice.sendATo(bob);
        System.out.printf("DH private key for Bob y: %s\n", bob.getPrivateKey());
        System.out.printf("Keys K0, K1 derived by Bob: (%s, %s)\n", bob.getK0(), bob.getK1());
        System.out.printf("Printing sigB: %s\n", bob.getSigB());
        System.out.printf("Printing tagB: %s\n", bob.getTagB());

        bob.sendBTo(alice);
        System.out.printf("Printing sigA: %s\n", alice.getSigA());
        System.out.printf("Printing tagA: %s\n", alice.getTagA());
        System.out.printf("Keys K0, K1 derived by Alice: (%s, %s)\n", alice.getK0(), alice.getK1());

        alice.sendCTo(bob);
        System.out.println("----------------------------");
    }
}

class Alice {
    private BigInteger x;
    private BigInteger g;
    private BigInteger q;
    private BigInteger X;
    private BigInteger T;
    private SigningKey skA;
    private VerificationKey vkA;
    private VerificationKey vkB;
    private Signature sigA;
    private BigInteger tagA;
    private BigInteger idA;
    private BigInteger k0;
    private BigInteger k1;

    private Alice() {
    }

    public static Alice initKeyGen(BigInteger g, BigInteger p, BigInteger q) {
        Alice alice = new Alice();
        alice.q = q;
        alice.g = g;
        alice.x = new BigInteger(q.bitLength() - 1, new Random());
        alice.X = alice.g.modPow(alice.x, alice.q);
        alice.T = new BigInteger(32, new Random());

        KeyGen keyGen = new KeyGen(p, q);
        KeyPair keyPairA = keyGen.init();
        alice.skA = keyPairA.getSigningKey();
        alice.vkA = keyPairA.getVerificationKey();

        return alice;
    }

    public BigInteger getPrivateKey() {
        return x;
    }

    public void sendATo(Bob bob) {
        bob.receive(this.T, this.X);
    }

    public BigInteger getK0() {
        return this.k0;
    }


    public BigInteger getK1() {
        return this.k1;
    }

    public Signature getSigA() {
        return sigA;
    }

    public BigInteger getTagA() {
        return tagA;
    }

    public void receive(BigInteger t, BigInteger Y, BigInteger idB, BigInteger tagB, Signature sigB) {
        this.T = t;

        //on receive action
        BigInteger Z = Y.modPow(this.x, q);
        String binaryString = Utils.sha256(Z).toString(2);
        this.k0 = new BigInteger(binaryString.substring(0, binaryString.length() / 2), 2);
        this.k1 = new BigInteger(binaryString.substring(binaryString.length() / 2), 2);
        BigInteger tagDash = Utils.hmac(k1, String.format("%s%s", this.T, idB));


        System.out.printf("\nTag and signature verification results by Alice:\nTag verification: %s.\n", tagDash.equals(tagB) ? "SUCCESS" : "FAILED");

        BigInteger m = new BigInteger(String.format("%s%s%s", this.T, this.X, Y));
        boolean isValid = Utils.verifySignature(vkB, m, sigB);
        System.out.printf("Signature verification: %s.\n\n", isValid ? "SUCCESS" : "FAILED");

        this.sigA = Utils.getSignature(this.skA, this.vkA, new BigInteger(String.format("%s%s%s", this.T, Y, X)));
        this.idA = new BigInteger(32, new Random());
        this.tagA = Utils.hmac(k1, String.format("%s%s", this.T, idA));
    }

    public void setVerificationKey(VerificationKey vkB) {
        this.vkB = vkB;
    }

    public VerificationKey getVerificationKey() {
        return vkA;
    }

    public void sendCTo(Bob bob) {
        bob.receive(this.T, this.idA, this.tagA, this.sigA);
    }
}

class Bob {

    private BigInteger y;
    private BigInteger g;
    private BigInteger q;
    private BigInteger X;
    private BigInteger Y;
    private BigInteger T;
    private SigningKey skB;
    private VerificationKey vkB;

    private VerificationKey vkA;
    private Signature sigB;
    private BigInteger tagB;
    private BigInteger idB;
    private BigInteger k0;
    private BigInteger k1;

    private Bob() {
    }

    public static Bob initKeyGen(BigInteger g, BigInteger p, BigInteger q) {
        Bob bob = new Bob();
        bob.g = g;
        bob.q = q;
        KeyGen keyGen = new KeyGen(p, q);
        KeyPair keyPairB = keyGen.init();
        bob.skB = keyPairB.getSigningKey();
        bob.vkB = keyPairB.getVerificationKey();
        return bob;
    }

    public BigInteger getPrivateKey() {
        return this.y;
    }

    public VerificationKey getVerificationKey() {
        return this.vkB;
    }

    public BigInteger getK0() {
        return this.k0;
    }


    public BigInteger getK1() {
        return this.k1;
    }

    public Signature getSigB() {
        return sigB;
    }

    public BigInteger getTagB() {
        return tagB;
    }

    public void sendBTo(Alice alice) {
        alice.receive(this.T, this.Y, this.idB, this.tagB, this.sigB);
    }

    public void setVerificationKey(VerificationKey vkA) {
        this.vkA = vkA;
    }

    public void receive(BigInteger T, BigInteger X) {
        this.T = T;
        this.X = X;

        //on receive action
        this.y = new BigInteger(this.q.bitLength() - 1, new Random());
        BigInteger Z = X.modPow(y, q);
        String binaryString = Utils.sha256(Z).toString(2);
        k0 = new BigInteger(binaryString.substring(0, binaryString.length() / 2), 2);
        k1 = new BigInteger(binaryString.substring(binaryString.length() / 2), 2);
        this.Y = g.modPow(y, this.q);
        this.sigB = Utils.getSignature(this.skB, this.vkB, new BigInteger(String.format("%s%s%s", this.T, X, this.Y)));
        this.idB = new BigInteger(32, new Random());
        this.tagB = Utils.hmac(k1, String.format("%s%s", this.T, idB));
    }

    public void receive(BigInteger T, BigInteger idA, BigInteger tagA, Signature sigA) {
        BigInteger tagDash = Utils.hmac(this.k1, String.format("%s%s", T, idA));
        System.out.printf("\nTag and signature verification results by Alice:\nTag verification: %s\n", tagDash.equals(tagA) ? "SUCCESS" : "FAILURE");

        BigInteger m = new BigInteger(String.format("%s%s%s", this.T, this.Y, this.X));
        boolean isValid = Utils.verifySignature(vkA, m, sigA);
        System.out.printf("Signature verification: %s.\n\n", isValid ? "SUCCESS" : "FAILED");
    }
}

class Utils {
    public static BigInteger sha256(BigInteger input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return new BigInteger(md.digest(input.toByteArray()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return BigInteger.ONE;
    }

    public static BigInteger hmac(BigInteger key, String message) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return new BigInteger(md.digest(key.toString().concat(message).getBytes()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return BigInteger.ONE;
    }

    public static Signature getSignature(SigningKey signingKey, VerificationKey verificationKey, BigInteger m) {
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

    public static boolean verifySignature(VerificationKey verificationKey, BigInteger m, Signature signature) {
        BigInteger p = verificationKey.getP();
        BigInteger q = verificationKey.getQ();
        BigInteger y = verificationKey.getY();
        BigInteger h = verificationKey.getH();
        BigInteger s = signature.getS();
        BigInteger r = signature.getR();
        BigInteger w = s.modInverse(q);
        BigInteger u1 = w.multiply(Utils.sha256(m)).mod(q);
        BigInteger u2 = r.multiply(w).mod(q);
        BigInteger v = ((h.modPow(u1, p).multiply(y.modPow(u2, p))).mod(p)).mod(q);
        return v.compareTo(r) == 0;
    }
}