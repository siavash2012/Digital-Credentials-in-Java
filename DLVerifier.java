
/*The code is implemented by Siavash Khalaj (skhal045@uottawa.ca) based on
 “Introduction to Privacy Enhancing Technologies“ (pages 124-130) by Professor Carlisle Adams*/

import org.bouncycastle.util.BigIntegers;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class DLVerifier {

    public BigInteger verifierC;

    public boolean verifySignature(DLUser user) throws NoSuchAlgorithmException {
        BigInteger gZeroCZeroPrime = user.discreteLogCA.g0.modPow(user.cZeroPrime, user.discreteLogCA.prime);
        BigInteger hRZeroPrime = user.h.modPow(user.rZeroPrime, user.discreteLogCA.prime);
        BigInteger toBeConcatenated = (gZeroCZeroPrime.multiply(hRZeroPrime)).mod(user.discreteLogCA.prime);
        BigInteger verification = concatenateBigIntegersHashed(user.h, toBeConcatenated);
        boolean result = verification.equals(user.cZeroPrime);
        if(!result){
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

    public BigInteger getVerifierC(DLUser user) {
        verifierC =  BigIntegers.createRandomInRange(BigInteger.TWO, user.discreteLogCA.qOrder.subtract(BigInteger.ONE), new SecureRandom());
        return verifierC;
    }

    public String stringToAscii(String str) {
        StringBuilder sum = new StringBuilder();
        for (int i = 0; i < str.length(); i++) {
            sum.append(Integer.toString(str.charAt(i), 16));

        }
        return sum.toString();
    }

    public boolean verifyShownAttributes(DLUser user, String[] shownStringAttributesArray, int[] shownGeneratorsArrayIndices, int[] concealedGeneratorsArrayIndices, BigInteger cPrime, BigInteger[] concealedRsArray, BigInteger a){

        int i;
        BigInteger hRaisedToCPrime = user.h.modPow(cPrime, user.discreteLogCA.prime);
        BigInteger hRaisedToCPrimeA = (hRaisedToCPrime.multiply(a)).mod(user.discreteLogCA.prime);
        BigInteger shownGeneratorsRaisedToShownXAttributes = BigInteger.ONE;
        BigInteger[] shownXAttributesArray = new BigInteger[shownStringAttributesArray.length];
        for(i=0; i< shownXAttributesArray.length; ++i){
            shownXAttributesArray[i]= new BigInteger(stringToAscii(shownStringAttributesArray[i]) ,16);
        }


        for(i = 0; i<shownXAttributesArray.length; ++i){
            shownGeneratorsRaisedToShownXAttributes = shownGeneratorsRaisedToShownXAttributes.multiply(user.discreteLogCA.generatorsArray[shownGeneratorsArrayIndices[i]].modPow((shownXAttributesArray[i].multiply(verifierC)), user.discreteLogCA.prime));
        }


        BigInteger concealedGeneratorsRaisedToConcealedRs = BigInteger.ONE;
        for(i=0; i< concealedGeneratorsArrayIndices.length; ++i){
            concealedGeneratorsRaisedToConcealedRs = concealedGeneratorsRaisedToConcealedRs.multiply(user.discreteLogCA.generatorsArray[
                    concealedGeneratorsArrayIndices[i]].modPow(concealedRsArray[i], user.discreteLogCA.prime)
            );
        }

        BigInteger hZeroRaisedToC = user.discreteLogCA.hZero.modPow(verifierC, user.discreteLogCA.prime);

        BigInteger verification = hZeroRaisedToC.multiply(concealedGeneratorsRaisedToConcealedRs).multiply(shownGeneratorsRaisedToShownXAttributes);
        verification = verification.mod(user.discreteLogCA.prime);

        boolean result = verification.equals(hRaisedToCPrimeA);
        if(!result){
            System.out.println("Attribute(s) Cannot Be Verified");
        }

        return result;

    }

    public boolean verifyShownAttributes(DLUser user, int ... shownAttributesIndices) throws NoSuchAlgorithmException {

        return user.showAttributes(this, shownAttributesIndices);

    }
}
