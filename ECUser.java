
/*The code is implemented by Siavash Khalaj (skhal045@uottawa.ca) based on
 “Introduction to Privacy Enhancing Technologies“ (pages 124-130) by Professor Carlisle Adams*/

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ECUser {

    private String[] stringAttributesArray;
    private BigInteger[] xAttributesArray;
    public ECCA ellipticCurveCA;
    MessageDigest hash;
    private BigInteger alpha;
    private BigInteger beta;
    private BigInteger gamma;
    public ECPoint h;
    public BigInteger cZeroPrime;
    public BigInteger rZeroPrime;


    public ECUser(ECCA ellipticCurveCA, String ... args) throws NoSuchAlgorithmException {

        this.ellipticCurveCA = ellipticCurveCA;
        if(args.length > ellipticCurveCA.generatorsArray.length){
            throw new IllegalArgumentException("Number of Attributes in User Constructor is Greater than the number of CA's generators");
        }
        stringAttributesArray = args.clone();
        xAttributesArray = new BigInteger[stringAttributesArray.length];
        for(int i=0; i<stringAttributesArray.length; ++i){
            xAttributesArray[i] = new BigInteger(stringToAscii(stringAttributesArray[i]), 16);
        }
        hash = MessageDigest.getInstance("sha-256");
        alpha = getRandomBigInteger();
        beta = getRandomBigInteger();
        gamma = getRandomBigInteger();
        h = computeH();

    }

    public BigInteger[] getXAttributesArray(){
        return xAttributesArray;
    }

    public BigInteger concatenateBigIntegersHashed(BigInteger a, BigInteger b) {

        byte[] aStringBytes = a.toByteArray();
        byte[] bStringBytes = b.toByteArray();
        byte[] concatBytesArray = new byte[aStringBytes.length + bStringBytes.length];
        for (int i = 0; i < aStringBytes.length; ++i) {
            concatBytesArray[i] = aStringBytes[i];
        }
        int index = 0;

        for (int i = aStringBytes.length; i < concatBytesArray.length; ++i) {
            concatBytesArray[i] = bStringBytes[index];
            index += 1;
        }
        byte[] resultBytes = this.hash.digest(concatBytesArray);
        return new BigInteger(1, resultBytes);

    }

    public void getAttributesSigned(){
        cZeroPrime = computeCZeroPrime();
        BigInteger cZero = computeCZero();
        BigInteger rZero = ellipticCurveCA.computeRZero(this,cZero);
        if(!verifyRZero(rZero,cZero)){
            System.out.println("Error! r received from the CA is not valid.");
            return;
        }
        BigInteger numerator = rZero.add(this.gamma);
        BigInteger denominator = (this.alpha).modInverse(ellipticCurveCA.qOrder);
        this.rZeroPrime = (numerator.multiply(denominator)).mod(ellipticCurveCA.qOrder);
    }


    private ECPoint computeH() {
        ECPoint h = ellipticCurveCA.bcCurve.getInfinity();
        for(int i=0; i<xAttributesArray.length; ++i){
            h = h.add(ellipticCurveCA.generatorsArray[i].multiply(xAttributesArray[i]));
        }
        h=h.add(ellipticCurveCA.hZero);
        h= h.multiply(this.alpha);
        return h.normalize();
    }


    private BigInteger computeCZeroPrime() {

        ellipticCurveCA.computeAZero();
        ECPoint gZeroBeta = (ellipticCurveCA.g0).multiply(this.beta);
        ECPoint hPrime = ellipticCurveCA.bcCurve.getInfinity();
        for(int i=0; i<xAttributesArray.length; ++i){
            hPrime = hPrime.add(ellipticCurveCA.generatorsArray[i].multiply(xAttributesArray[i]));
        }
        hPrime=hPrime.add(ellipticCurveCA.hZero);
        hPrime=hPrime.multiply(this.gamma);
        ECPoint toBeConcatenated = gZeroBeta.add(hPrime).add(ellipticCurveCA.aZero);
        toBeConcatenated = toBeConcatenated.normalize();
        BigInteger cZeroPrime = concatenateBigIntegersHashed(this.h.getAffineXCoord().toBigInteger(), toBeConcatenated.getAffineXCoord().toBigInteger());
        return cZeroPrime;
    }


    private BigInteger computeCZero() {

        return (cZeroPrime.subtract(this.beta)).mod(ellipticCurveCA.qOrder);
    }


    private boolean verifyRZero(BigInteger rZero, BigInteger cZero) {

        ECPoint gZeroCzero = (ellipticCurveCA.g0).multiply(cZero);
        ECPoint hPrime = ellipticCurveCA.bcCurve.getInfinity();
        for(int i=0; i<xAttributesArray.length; ++i){
            hPrime = hPrime.add(ellipticCurveCA.generatorsArray[i].multiply(xAttributesArray[i]));
        }
        hPrime=hPrime.add(ellipticCurveCA.hZero);
        hPrime = hPrime.multiply(rZero);
        ECPoint verification = hPrime.add(gZeroCzero);
        return verification.equals(ellipticCurveCA.aZero);
    }


    public String stringToAscii(String str) {

        StringBuilder sum = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            sum.append(Integer.toString(str.charAt(i), 16));

        }
        return sum.toString();
    }

    public BigInteger getRandomBigInteger() {

        BigInteger min = BigInteger.TWO;
        BigInteger max = ellipticCurveCA.qOrder.subtract(BigInteger.ONE);
        SecureRandom secureRandom =  new SecureRandom();
        return BigIntegers.createRandomInRange(min, max,secureRandom);
    }




    public boolean showAttributes(ECVerifier verifier, int ... shownAttributesIndices) throws NoSuchAlgorithmException {

        if(shownAttributesIndices.length > xAttributesArray.length){
            throw new IllegalArgumentException("Number of Shown Attributes is Greater than the User's Number of Attributes");
        }

        if(! verifier.verifySignature(this)){
            System.out.println("Error! The user signature cannot be verified");
            return false;
        }
        int i,j;
        int indexShown = 0;
        int indexConcealed = 0;
        int concealedArraysLength = xAttributesArray.length - shownAttributesIndices.length;
        BigInteger w = getRandomBigInteger();
        String[] shownStringAttributesArray = new String[shownAttributesIndices.length];
        BigInteger[] concealedXAttributesArray = new BigInteger[concealedArraysLength];
        BigInteger[] wSArray = new BigInteger[concealedArraysLength];
        int[] concealedGeneratorsArrayIndices = new int[concealedArraysLength];
        int[] shownGeneratorsArrayIndices = new int[shownAttributesIndices.length];
        BigInteger[] concealedRsArray = new BigInteger[concealedArraysLength];
        boolean indexFound = false;
        for(i=0; i<xAttributesArray.length; ++i){
            for(j=0;j<shownAttributesIndices.length;++j){
                if(shownAttributesIndices[j] > xAttributesArray.length-1){
                    throw new IllegalArgumentException("Shown Attributes index "+ shownAttributesIndices[j] + " does not exist");
                }
                if(i == shownAttributesIndices[j]){
                   indexFound = true;
                }
            }
            if(indexFound){
                shownStringAttributesArray[indexShown] = stringAttributesArray[i];
                shownGeneratorsArrayIndices[indexShown] = i;
                ++indexShown;
            }
            if(!indexFound){
                    concealedXAttributesArray[indexConcealed] = xAttributesArray[i];
                    wSArray[indexConcealed] = getRandomBigInteger();
                    concealedGeneratorsArrayIndices[indexConcealed] = i;
                    ++indexConcealed;
            }
            indexFound = false;
        }

        ECPoint hRaisedToWInverse = (this.h.multiply(w)).negate();

        ECPoint concealedGeneratorsRaisedToWs = ellipticCurveCA.bcCurve.getInfinity();

        for(i=0; i<concealedArraysLength; ++i){
            concealedGeneratorsRaisedToWs = concealedGeneratorsRaisedToWs.add(ellipticCurveCA.generatorsArray[concealedGeneratorsArrayIndices[i]].multiply(wSArray[i]));
        }

        ECPoint a = (hRaisedToWInverse.add(concealedGeneratorsRaisedToWs));
        BigInteger verifierC = verifier.getVerifierC(this);
        BigInteger cPrime = verifierC.multiply(this.alpha.modInverse(ellipticCurveCA.qOrder));
        cPrime = cPrime.add(w);
        cPrime = cPrime.mod(ellipticCurveCA.qOrder);

        for(i=0; i<concealedArraysLength; ++i){
            concealedRsArray[i] = verifierC.multiply(concealedXAttributesArray[i]);
            concealedRsArray[i] = concealedRsArray[i].add(wSArray[i]);
            concealedRsArray[i] = concealedRsArray[i].mod(ellipticCurveCA.qOrder);
        }

        return verifier.verifyShownAttributes(this, shownStringAttributesArray, shownGeneratorsArrayIndices, concealedGeneratorsArrayIndices, cPrime, concealedRsArray, a);

    }

    public String toString(){
        StringBuilder user = new StringBuilder();
        for(int i=0; i<stringAttributesArray.length; ++i){
            user.append("Attribute ");
            user.append(i + 1);
            user.append(": ");
            user.append(stringAttributesArray[i]);
            user.append("\n");
        }

        return user.toString();
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {

        ECCA ellipticCurveCA = new ECCA(20);
        ECVerifier verifier = new ECVerifier();

        ECUser Alice = new ECUser(ellipticCurveCA,"Alice", "Allison", "1979/09/19", "541 5th Ave. N",
                "Saskatoon", "SK", "S7K5Z9","Visa","12345678",
                "2023/12");
        Alice.getAttributesSigned();
        System.out.println(verifier.verifySignature(Alice));
        System.out.println(verifier.verifyShownAttributes(Alice,0));
        System.out.println(verifier.verifyShownAttributes(Alice,0,1));
        System.out.println(verifier.verifyShownAttributes(Alice,0,1,2));
        System.out.println(verifier.verifyShownAttributes(Alice,0,1,2,3));
        System.out.println(verifier.verifyShownAttributes(Alice,0,1,2,3,4));
        System.out.println(verifier.verifyShownAttributes(Alice,0,1,2,3,4,5));
        System.out.println(verifier.verifyShownAttributes(Alice,0,1,2,3,4,5,6));
        System.out.println(verifier.verifyShownAttributes(Alice,0,1,2,3,4,5,6,7));
        System.out.println(verifier.verifyShownAttributes(Alice,0,1,2,3,4,5,6,7,8));
        System.out.println(verifier.verifyShownAttributes(Alice,0,1,2,3,4,5,6,7,8,9));

        ECUser Bob = new ECUser(ellipticCurveCA, "Bob","Johnson","1987");
        Bob.getAttributesSigned();
        System.out.println(verifier.verifySignature(Bob));
        System.out.println(Bob.showAttributes(verifier,0));
        System.out.println(Bob.showAttributes(verifier,1));
        System.out.println(Bob.showAttributes(verifier,2,1,0));

    }

}

