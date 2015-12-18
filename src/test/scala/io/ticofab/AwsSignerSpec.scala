package io.ticofab

import com.amazonaws.auth.{AWSCredentials, AWSCredentialsProvider, BasicAWSCredentials}
import com.amazonaws.internal.StaticCredentialsProvider
import org.joda.time.DateTime
import org.scalatest.{FlatSpec, Matchers}

import scala.collection.immutable.TreeMap

class AwsSignerSpec extends FlatSpec with Matchers {
  /**
    * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
    * (get-vanilla.*)
    *
    * GET / http/1.1
    * Date:Mon, 09 Sep 2011 23:36:00 GMT
    * Host:host.foo.com
    *
    */
  "AwsSigner" should "produce the expected result" in {

    // GIVEN
    // Credentials
    val awsAccessKey = "AKIDEXAMPLE"
    val awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    val credentials: AWSCredentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey)
    val awsCredentialsProvider: AWSCredentialsProvider = new StaticCredentialsProvider(credentials)
    val region = "us-east-1"
    val service = "host"

    def clock(): DateTime = new DateTime().withDate(2011, 9, 9).withHourOfDay(23).withMinuteOfHour(36).withSecondOfMinute(0)
    val date = "Mon, 09 Sep 2011 23:36:00 GMT"

    val host = "host.foo.com"
    val uri = "/"
    val method = "GET"
    val queryParams = Map[String, String]()
    val headers: Map[String, Object] = Map("Date" -> date, "Host" -> host)
    val payload: Option[Array[Byte]] = None

    val signer: AwsSigner = AwsSigner(awsCredentialsProvider, region, service, clock)
    val signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload)

    // The signature must match the expected signature
    val expectedSignature = "b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470"
    val expectedAuthorizationHeader = String.format(
      "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
      awsAccessKey, region, service, expectedSignature
    )

    var caseInsensitiveSignedHeaders = new TreeMap[String, String]
    caseInsensitiveSignedHeaders ++= signedHeaders
    assert(caseInsensitiveSignedHeaders.contains("Authorization"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(caseInsensitiveSignedHeaders.contains("Host"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Host", "").equals(host))
    assert(caseInsensitiveSignedHeaders.contains("Date"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Date", "").equals(date))
    assert(!caseInsensitiveSignedHeaders.contains("X-Amz-Date"))

  }
}


/**
  * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
  * (get-vanilla.*)
  *
  * GET / http/1.1
  * Date:Mon, 09 Sep 2011 23:36:00 GMT
  * Host:host.foo.com
  *
  * @throws Exception
  */
/*
@Test
public void testGetVanilla () throws Exception {
// GIVEN
// Credentials
String awsAccessKey = "AKIDEXAMPLE";
String awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
AWSCredentials credentials = new BasicAWSCredentials (awsAccessKey, awsSecretKey);
AWSCredentialsProvider awsCredentialsProvider = new StaticCredentialsProvider (credentials);
String region = "us-east-1";
String service = "host";

// Date
Supplier < LocalDateTime > clock = () -> LocalDateTime.of (2011, 9, 9, 23, 36, 0);
// weird date : 09 Sep 2011 is a friday, not a monday
String date = "Mon, 09 Sep 2011 23:36:00 GMT";

// HTTP request
String host = "host.foo.com";
String uri = "/";
String method = "GET";
Map < String, String > queryParams = ImmutableMap.< String, String > builder ()
.build ();
Map < String, Object > headers = ImmutableMap.< String, Object > builder ()
.put ("Date", date)
.put ("Host", host)
.build ();
Optional < byte[] > payload = Optional.absent ();

// WHEN
// The request is signed
AWSSigner signer = new AWSSigner (awsCredentialsProvider, region, service, clock);
Map < String, Object > signedHeaders = signer.getSignedHeaders (uri, method, queryParams, headers, payload);

// THEN
// The signature must match the expected signature
String expectedSignature = "b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470";
String expectedAuthorizationHeader = format (
"AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
awsAccessKey, region, service, expectedSignature
);

TreeMap < String, Object > caseInsensitiveSignedHeaders = new TreeMap <> (String.CASE_INSENSITIVE_ORDER);
caseInsensitiveSignedHeaders.putAll (signedHeaders);
assertThat (caseInsensitiveSignedHeaders).containsKey ("Authorization");
assertThat (caseInsensitiveSignedHeaders.get ("Authorization") ).isEqualTo (expectedAuthorizationHeader);
assertThat (caseInsensitiveSignedHeaders).containsKey ("Host");
assertThat (caseInsensitiveSignedHeaders.get ("Host") ).isEqualTo (host);
assertThat (caseInsensitiveSignedHeaders).containsKey ("Date");
assertThat (caseInsensitiveSignedHeaders.get ("Date") ).isEqualTo (date);
assertThat (caseInsensitiveSignedHeaders).doesNotContainKey ("X-Amz-Date");
}

}
*/