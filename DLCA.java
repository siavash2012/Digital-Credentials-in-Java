
/*The code is implemented by Siavash Khalaj (skhal045@uottawa.ca) based on
 “Introduction to Privacy Enhancing Technologies“ (pages 124-130) by Professor Carlisle Adams*/

import org.bouncycastle.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;

public class DLCA {
    //BigIntegers prime, g0, ... gn, and hZero are public keys of the CA
    public BigInteger prime;
    public BigInteger qOrder;
    public BigInteger g0;
    public BigInteger[] generatorsArray;
    public BigInteger hZero;
    BigInteger wZero;
    BigInteger aZero;
    //BigIntegers xPrivateKey, y1, ... yn are random numbers which are private keys of the CA
    private BigInteger xPrivateKey;
    private BigInteger[] yPrivateKeysArray;

    public DLCA(int numberOfGenerators){

        //3072-bit prime with generator 2 obtained from https://www.ietf.org/rfc/rfc3526.txt
        this.prime = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
                "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
                "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
                "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
                "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
                "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);

        qOrder = (this.prime.subtract(BigInteger.ONE)).divide(BigInteger.TWO);
        xPrivateKey = getRandomBigInteger();
        yPrivateKeysArray = new BigInteger[numberOfGenerators];
        for(int i=0; i< yPrivateKeysArray.length;++i){
            yPrivateKeysArray[i] = getRandomBigInteger();
        }

        g0 = new BigInteger("2",16);
        generatorsArray = new BigInteger[yPrivateKeysArray.length];
        for(int i=0; i<generatorsArray.length; ++i){
            generatorsArray[i] = g0.modPow(yPrivateKeysArray[i], prime);
        }
        hZero = g0.modPow(xPrivateKey,prime);
    }


    public BigInteger getRandomBigInteger() {

        BigInteger min = BigInteger.TWO;
        BigInteger max = qOrder.subtract(BigInteger.ONE);
        SecureRandom secureRandom =  new SecureRandom();
        return BigIntegers.createRandomInRange(min, max,secureRandom);
    }



    public void computeAZero(){

        this.wZero = getRandomBigInteger();
        this.aZero = g0.modPow(wZero, prime);
    }

    private BigInteger computeUserXy(BigInteger[] userXAttributesArray){
        BigInteger sum = BigInteger.ZERO;
        for(int i =0; i< userXAttributesArray.length; ++i){
            sum = sum.add(userXAttributesArray[i].multiply(yPrivateKeysArray[i]));
        }
        return sum;

    }

    public BigInteger computeRZero(DLUser user, BigInteger cZero){

       BigInteger denominator = this.xPrivateKey.add(computeUserXy(user.getXAttributesArray()));
       BigInteger numerator = this.wZero.subtract(cZero);
       denominator = denominator.modInverse(qOrder);
       return (numerator.multiply(denominator)).mod(qOrder);

    }

}
