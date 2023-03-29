
/*The code is implemented by Siavash Khalaj (skhal045@uottawa.ca) based on
 “Introduction to Privacy Enhancing Technologies“ (pages 124-130) by Professor Carlisle Adams*/

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;



public class ECVerifier {

    public BigInteger verifierC;

    public boolean verifySignature(ECUser user) throws NoSuchAlgorithmException {
        ECPoint gZeroCZeroPrime = user.ellipticCurveCA.g0.multiply(user.cZeroPrime);
        ECPoint hRZeroPrime = user.h.multiply(user.rZeroPrime);
        ECPoint toBeConcatenated = gZeroCZeroPrime.add(hRZeroPrime);
        toBeConcatenated = toBeConcatenated.normalize();
        BigInteger verification = concatenateBigIntegersHashed(user.h.getAffineXCoord().toBigInteger(), toBeConcatenated.getAffineXCoord().toBigInteger());
        boolean result = verification.equals(user.cZeroPrime);
        if (!result) {
            System.out.println("Signature Cannot Be Verified");
        }
        return result;
    }

    public BigInteger concatenateBigIntegersHashed(BigInteger a, BigInteger b) throws NoSuchAlgorithmException {

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
        MessageDigest hash = MessageDigest.getInstance("sha-256");
        byte[] resultBytes = hash.digest(concatBytesArray);
        return new BigInteger(1, resultBytes);

    }

    public BigInteger getVerifierC(ECUser user) {
        verifierC =  BigIntegers.createRandomInRange(BigInteger.TWO, user.ellipticCurveCA.qOrder.subtract(BigInteger.ONE), new SecureRandom());
        return verifierC;
    }

    public String stringToAscii(String str) {

        StringBuilder sum = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            sum.append(Integer.toString(str.charAt(i), 16));

        }
        return sum.toString();
    }

    public boolean verifyShownAttributes(ECUser user, String[] shownStringAttributesArray, int[] shownGeneratorsArrayIndices, int[] concealedGeneratorsArrayIndices, BigInteger cPrime, BigInteger[] concealedRsArray, ECPoint a) {

        int i;
        ECPoint hRaisedToCPrime = user.h.multiply(cPrime);
        ECPoint hRaisedToCPrimeA = hRaisedToCPrime.add(a);
        ECPoint shownGeneratorsRaisedToShownXAttributes = user.ellipticCurveCA.bcCurve.getInfinity();
        BigInteger[] shownXAttributesArray = new BigInteger[shownStringAttributesArray.length];
        for(i=0; i< shownXAttributesArray.length; ++i){
            shownXAttributesArray[i]= new BigInteger(stringToAscii(shownStringAttributesArray[i]) ,16);
        }

        for(i = 0; i<shownXAttributesArray.length; ++i){
            shownGeneratorsRaisedToShownXAttributes = shownGeneratorsRaisedToShownXAttributes.add(user.ellipticCurveCA.generatorsArray[shownGeneratorsArrayIndices[i]].multiply((shownXAttributesArray[i].multiply(verifierC))));
        }


        ECPoint concealedGeneratorsRaisedToConcealedRs = user.ellipticCurveCA.bcCurve.getInfinity();
        for(i=0; i< concealedGeneratorsArrayIndices.length; ++i){
            concealedGeneratorsRaisedToConcealedRs = concealedGeneratorsRaisedToConcealedRs.add(
                    user.ellipticCurveCA.generatorsArray[concealedGeneratorsArrayIndices[i]].multiply(concealedRsArray[i]));
        }

        ECPoint hZeroRaisedToC = user.ellipticCurveCA.hZero.multiply(verifierC);

        ECPoint verification = hZeroRaisedToC.add(concealedGeneratorsRaisedToConcealedRs).add(shownGeneratorsRaisedToShownXAttributes);

        boolean result = verification.equals(hRaisedToCPrimeA);
        if(!result){
            System.out.println("Attribute(s) Cannot Be Verified");
        }

        return result;

    }

    public boolean verifyShownAttributes(ECUser user, int... shownAttributesIndices) throws NoSuchAlgorithmException {

        return user.showAttributes(this, shownAttributesIndices);

    }
}
