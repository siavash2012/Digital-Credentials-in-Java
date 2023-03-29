
/*The code is implemented by Siavash Khalaj (skhal045@uottawa.ca) based on
 “Introduction to Privacy Enhancing Technologies“ (pages 124-130) by Professor Carlisle Adams*/

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Enumeration;


public class ECCA {

    //BigIntegers prime, g0, ... gn (generatorsArray elements), and h0 are public keys of the CA
    public BigInteger qOrder;
    public ECPoint g0;
    public ECPoint[] generatorsArray;
    public ECPoint hZero;
    public BigInteger wZero;
    public ECPoint aZero;

    //BigIntegers xPrivateKey, y1, ... yn are random numbers which are private keys of the CA
    private BigInteger xPrivateKey;
    private BigInteger[] yPrivateKeysArray;
    public org.bouncycastle.math.ec.ECCurve bcCurve;
    private ECNamedCurveParameterSpec spec;

    public ECCA(int numberOfGenerators){

        spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        bcCurve = spec.getCurve();
        qOrder = bcCurve.getOrder();
        xPrivateKey = getRandomBigInteger();
        yPrivateKeysArray = new BigInteger[numberOfGenerators];
        for(int i=0; i< yPrivateKeysArray.length;++i){
            yPrivateKeysArray[i] = getRandomBigInteger();
        }

        g0 = spec.getG();
        generatorsArray = new ECPoint[yPrivateKeysArray.length];
        for(int i=0; i<generatorsArray.length; ++i){
            generatorsArray[i] = g0.multiply(yPrivateKeysArray[i]);
        }

        hZero = g0.multiply(xPrivateKey);
    }

    public BigInteger getRandomBigInteger() {

        BigInteger min = BigInteger.TWO;
        BigInteger max = qOrder.subtract(BigInteger.ONE);
        SecureRandom secureRandom =  new SecureRandom();
        return BigIntegers.createRandomInRange(min, max,secureRandom);
    }


    public void computeAZero(){

        this.wZero = getRandomBigInteger();
        this.aZero = g0.multiply(wZero);
    }

    private BigInteger computeUserXy(BigInteger[] userXAttributesArray){
        BigInteger sum = BigInteger.ZERO;
        for(int i =0; i< userXAttributesArray.length; ++i){
            sum = sum.add(userXAttributesArray[i].multiply(yPrivateKeysArray[i]));
        }
        return sum;

    }

    public BigInteger computeRZero(ECUser user, BigInteger cZero){

        BigInteger denominator = this.xPrivateKey.add(computeUserXy(user.getXAttributesArray()));
        BigInteger numerator = this.wZero.subtract(cZero);
        denominator = denominator.modInverse(qOrder);
        return (numerator.multiply(denominator)).mod(qOrder);

    }



    /*public static void main(String[] args){

        SECNamedCurves secNames = new SECNamedCurves();
        Enumeration enSec=secNames.getNames();
        int count=0;
        while(enSec.hasMoreElements()){
            System.out.print(enSec.nextElement().toString());
            System.out.print("\t");
            ++count;
            if(count %5==0){
                System.out.println();
            }
        }
    }*/

    public static void main(String[] args){
        //creating a random point for testing
        ECCA testCA = new ECCA(5);
        ECPoint testPoint = testCA.g0.multiply(new BigInteger("128"));
        //use false for encoding without compression, true for encoding in compressed format
        byte[] testPointBytes = testPoint.getEncoded(false);
        ECPoint testPointFromBytes = testCA.bcCurve.decodePoint(testPointBytes);
        System.out.println(testPoint.equals(testPointFromBytes));
        //The points are equal, but for printing and visualizing equality, normalize the point to convert from Jacobian coordinates to affine coordinates
        System.out.println(testPoint.normalize());
        System.out.println(testPointFromBytes);
    }

}
