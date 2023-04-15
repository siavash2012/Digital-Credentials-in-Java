
/*The code is implemented by Siavash Khalaj (skhal045@uottawa.ca)*/

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;


public class TextIO {

    String[] wordsArray;
    ArrayList<String> fileDataArray = new ArrayList<>();
    FileWriter writer;

    public TextIO(String fileName) {

        try {
            writer = new FileWriter(fileName);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void write(long time) throws IOException {
        writer.write(Integer.toString((int)time) + "\t");
    }

    public void write(String input) throws IOException {
        writer.write(input);
    }

    public void close() throws IOException {
        writer.close();
    }


    public void readTestFile(String fileName) {

        try {
            BufferedReader buf = new BufferedReader(new FileReader(fileName));
            ArrayList<String> words = new ArrayList<>();
            String lineJustFetched = null;


            while (true) {
                lineJustFetched = buf.readLine();
                if (lineJustFetched == null) {
                    break;
                } else {
                    wordsArray = lineJustFetched.split("\t");
                    for (String each : wordsArray) {
                        if (!"".equals(each)) {
                            words.add(each);
                        }
                    }
                }
            }

            for (String each : words) {
                fileDataArray.add(each);

            }

            buf.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

