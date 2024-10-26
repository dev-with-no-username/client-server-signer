package aws.samples.sigv4a;

import com.sigv4aSigning.SigV4Sign;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;

/**
 * Unit test for simple App.
 */
public class SigV4SignTest
        extends TestCase {
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public SigV4SignTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(SigV4SignTest.class);
    }

    /**
     * Rigourous Test :-)
     */
    public void testSigV4ASign() {
        String accessKeyId = "test:kid";
        String secretAccessKey = "testkey";
        AwsCredentials awsCredentials = AwsBasicCredentials.create(accessKeyId, secretAccessKey);
        SigV4Sign.create(awsCredentials);
        assertTrue(true);
    }
}
