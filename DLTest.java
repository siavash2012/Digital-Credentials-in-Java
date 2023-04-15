
/*The code is implemented by Siavash Khalaj (skhal045@uottawa.ca)*/

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class DLTest {

    ArrayList<DLUser> userArray = new ArrayList<>();
    ArrayList<Long> gettingAttributesSignedTime = new ArrayList<>();
    ArrayList<Long> gettingSignatureVerifiedTime = new ArrayList<>();
    ArrayList<Long> showingOneAttributeTime = new ArrayList<>();
    ArrayList<Long> showingTwoAttributesTime = new ArrayList<>();
    ArrayList<Long> showingThreeAttributesTime = new ArrayList<>();
    ArrayList<Long> showingFourAttributesTime = new ArrayList<>();
    ArrayList<Long> showingFiveAttributesTime = new ArrayList<>();
    ArrayList<Long> showingSixAttributesTime = new ArrayList<>();
    ArrayList<Long> showingSevenAttributesTime = new ArrayList<>();
    ArrayList<Long> showingEightAttributesTime = new ArrayList<>();
    ArrayList<Long> showingNineAttributesTime = new ArrayList<>();
    ArrayList<Long> showingTenAttributesTime = new ArrayList<>();

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        DLCA discreteLogCA = new DLCA(10);
        DLVerifier verifier = new DLVerifier();
        TextIO textIO = new TextIO("book_implementation_DL_result.txt");
        DLTest test = new DLTest();
        textIO.readTestFile("user_information.txt");
        long startTime, endTime, duration;
        for (int i = 0; i < textIO.fileDataArray.size(); ++i) {
            DLUser user = new DLUser(
                    discreteLogCA,
                    textIO.fileDataArray.get(i),
                    textIO.fileDataArray.get(++i),
                    textIO.fileDataArray.get(++i),
                    textIO.fileDataArray.get(++i),
                    textIO.fileDataArray.get(++i),
                    textIO.fileDataArray.get(++i),
                    textIO.fileDataArray.get(++i),
                    textIO.fileDataArray.get(++i),
                    textIO.fileDataArray.get(++i),
                    textIO.fileDataArray.get(++i)
            );
            test.userArray.add(user);
        }


        for (int i = 0; i < test.userArray.size(); ++i) {
            System.out.println(i);
            startTime = System.nanoTime();
            test.userArray.get(i).getAttributesSigned();
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.gettingAttributesSignedTime.add(duration);

            startTime = System.nanoTime();
            verifier.verifySignature(test.userArray.get(i));
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.gettingSignatureVerifiedTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingOneAttributeTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0, 1);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingTwoAttributesTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0, 1, 2);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingThreeAttributesTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0, 1, 2, 3);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingFourAttributesTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0, 1, 2, 3, 4);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingFiveAttributesTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0, 1, 2, 3, 4, 5);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingSixAttributesTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0, 1, 2, 3, 4, 5, 6);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingSevenAttributesTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0, 1, 2, 3, 4, 5, 6, 7);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingEightAttributesTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0, 1, 2, 3, 4, 5, 6, 8);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingNineAttributesTime.add(duration);

            startTime = System.nanoTime();
            test.userArray.get(i).showAttributes(verifier, 0, 1, 2, 3, 4, 5, 6, 8, 9);
            endTime = System.nanoTime();
            duration = (endTime - startTime);
            test.showingTenAttributesTime.add(duration);
        }

        for (int i = 0; i < test.userArray.size(); ++i) {
            {

                textIO.write(test.gettingAttributesSignedTime.get(i));
                textIO.write(test.gettingSignatureVerifiedTime.get(i));
                textIO.write(test.showingOneAttributeTime.get(i));
                textIO.write(test.showingTwoAttributesTime.get(i));
                textIO.write(test.showingThreeAttributesTime.get(i));
                textIO.write(test.showingFourAttributesTime.get(i));
                textIO.write(test.showingFiveAttributesTime.get(i));
                textIO.write(test.showingSixAttributesTime.get(i));
                textIO.write(test.showingSevenAttributesTime.get(i));
                textIO.write(test.showingEightAttributesTime.get(i));
                textIO.write(test.showingNineAttributesTime.get(i));
                textIO.write(test.showingTenAttributesTime.get(i));
                textIO.write("\n");

            }
        }

        textIO.close();


    }
}
