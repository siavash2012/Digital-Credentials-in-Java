# Digital-Credentials-in-Java
Java implementation of Brand's Digital Credentials based on "Introduction to Privacy Enhancing Technologies" (pages 124-130) by Carlisle Adams
<h3 >Java implementation of Brand's Digital Credentials based on "Introduction to Privacy Enhancing Technologies" (pages 124-130) by Carlisle Adams.</h3>
<p>This repository includes the Java implemntation of Brand's Digital Credentials. Two versions of the protocols were implemented: Modulo p (discrete logarithm) and elliptic curve.</p>
<p>The discrete log version is implemented in the three classes DLUser (user Alice), DLCA (the Certification Authority), and DLVerifier (the verifier of Alice's digital signature and her attributes). The elliptic curve version is implemented in ECUser, ECCA, and ECVerifier classes. To run the files, download the Bouncy Castle JDK (https://www.bouncycastle.org/latest_releases.html) and add it to the project.</p>
<p>The files DLTest.java and ECTest.java time 12 operations (obtain signature from the CA, verify signature by the verifier, show 1 attribute to the verifier, show 2 attributes to the verifier, .... show 10 attributes to the verifer) for 1000 DLUser or ECUser objects instantiated with the attributes available in user_information.txt. TextIO.java is responsible for reading user_information.txt and writing the timing results to a tab-serparated CSV file.</p>
<p>The file digital_credentials_plot_test.py is a python script for reading the timing results from the output CSV files, plotting the results, and performing t tests.</p>
