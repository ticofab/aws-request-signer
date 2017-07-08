package io.ticofab

import java.lang.String._
import java.time.LocalDateTime

import com.amazonaws.auth._
import com.amazonaws.auth.profile.ProfileCredentialsProvider
import org.scalatest.{FlatSpec, Matchers}

class AwsSignerSpec extends FlatSpec with Matchers {

  // Test Credentials.
  val AwsAccessKey = "AKIDEXAMPLE"
  val AwsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
  val Credentials: AWSCredentials = new BasicAWSCredentials(AwsAccessKey, AwsSecretKey)
  val AwsCredentialsProvider: AWSCredentialsProvider = new AWSStaticCredentialsProvider(Credentials)
  val Region = "us-east-1"
  val Service = "service"

  // Test Credentials for testing with session token.
  val SessionToken: String = "AKIDEXAMPLESESSION"
  val CredentialsWithSession: AWSCredentials = new BasicSessionCredentials(AwsAccessKey, AwsSecretKey, SessionToken)
  val AwsCredentialsProviderWithSession: AWSCredentialsProvider = new AWSStaticCredentialsProvider(CredentialsWithSession)

  // Test Credentials using profile for testing with session token.
  val credentialsPath = getClass.getResource("/credentials").getPath
  val ProfileCredentialsWithSession: AWSCredentials = new ProfileCredentialsProvider(credentialsPath.toString, "default").getCredentials
  val awsProfileCredentialsProviderWithSession: AWSCredentialsProvider = new AWSStaticCredentialsProvider(CredentialsWithSession)

  // Static clock to ensure deterministic test results.
  val clock: () => LocalDateTime = () => LocalDateTime.of(2011, 9, 9, 23, 36, 0)

  // HTTP Request related properties.
  val PostMethod: String = "POST"
  val GetMethod: String = "GET"
  val Host: String = "host.foo.com"
  val Uri: String = "/"
  val EmptyQueryParams = Map[String, String]()
  val emptyPayload: Option[Array[Byte]] = None
  val hostHeader: Map[String, String] = Map("Host" -> Host)

  "AwsSigner" should "pass the GET vanilla test" in {

    // DATE
    // weird date : 09 Sep 2011 is a friday, not a monday
    val date = "Mon, 09 Sep 2011 23:36:00 GMT"

    // Header for HTTP Request.
    val headers: Map[String, String] = Map("Date" -> date) ++ hostHeader

    val signer: AwsSigner = AwsSigner(AwsCredentialsProvider, Region, Service, clock)
    val signedHeaders = signer.getSignedHeaders(Uri, GetMethod, EmptyQueryParams, headers, emptyPayload)

    // The signature must match the expected signature
    val expectedSignature = "b0a671385ef1f9513c15c34d206c7d83e3a4d848c43603569eca2760ee75c3b3"
    val expectedAuthorizationHeader = String.format(
      "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
      AwsAccessKey, Region, Service, expectedSignature
    )

    assert(signedHeaders.contains("Authorization"))
    assert(signedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(signedHeaders.contains("Host"))
    assert(signedHeaders.getOrElse("Host", "").equals(Host))
    assert(signedHeaders.contains("Date"))
    assert(signedHeaders.getOrElse("Date", "").equals(date))
    assert(!signedHeaders.contains("X-Amz-Date"))
  }

  /**
    * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
    */
  it should "pass the GET vanilla test with parameters" in {

    // DATE
    val xAmzDate = "20150830T123600Z"

    // HOST
    val host = "example.amazonaws.com"

    // Header for HTTP Request.
    val headers: Map[String, String] = Map("X-Amz-Date" -> xAmzDate, "Host" -> host)

    // parameters for HTTP request
    val params: Map[String, String] = EmptyQueryParams ++ Map("Param2" -> "value2", "Param1" -> "value1")

    val signer: AwsSigner = AwsSigner(AwsCredentialsProvider, Region, Service, () => LocalDateTime.of(2015, 8, 30, 12, 36, 0))
    val signedHeaders = signer.getSignedHeaders(Uri, GetMethod, params, headers, emptyPayload)

    // The signature must match the expected signature
    val expectedSignature = "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
    val expectedAuthorizationHeader = String.format(
      "AWS4-HMAC-SHA256 Credential=%s/20150830/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s",
      AwsAccessKey, Region, Service, expectedSignature
    )

    assert(signedHeaders.contains("Authorization"))
    assert(signedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(signedHeaders.contains("Host"))
    assert(signedHeaders.getOrElse("Host", "").equals(host))
    assert(signedHeaders.contains("X-Amz-Date"))
    assert(signedHeaders.getOrElse("X-Amz-Date", "").equals(xAmzDate))
  }

  it should "pass the POST query vanilla test" in {

    // weird date : 09 Sep 2011 is a friday, not a monday
    val date = "Mon, 09 Sep 2011 23:36:00 GMT"

    // Header && params for HTTP Request.
    val queryParams: Map[String, String] = EmptyQueryParams ++ Map("foo" -> "bar")
    val headers: Map[String, String] = Map("Date" -> date) ++ hostHeader

    // WHEN
    // The request is signed
    val signer: AwsSigner = AwsSigner(AwsCredentialsProvider, Region, Service, clock)
    val signedHeaders = signer.getSignedHeaders(Uri, PostMethod, queryParams, headers, emptyPayload)

    // THEN
    // The signature must match the expected signature
    val expectedSignature: String = "ffa9577fe836168407d8a9afce6d75e903de636017cb60bb37f4b094ecfb1c27"
    val expectedAuthorizationHeader: String = format("AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
      AwsAccessKey, Region, Service, expectedSignature)

    assert(signedHeaders.contains("Authorization"))
    assert(signedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(signedHeaders.contains("Host"))
    assert(signedHeaders.getOrElse("Host", "").equals(Host))
    assert(signedHeaders.contains("Date"))
    assert(signedHeaders.getOrElse("Date", "").equals(date))
    assert(!signedHeaders.contains("X-Amz-Date"))
  }

  it should "pass the GET vanilla test without Date Header" in {

    // weird date : 09 Sep 2011 is a friday, not a monday
    val date: String = "20110909T233600Z"

    // Header for HTTP Request.
    val headers: Map[String, String] = hostHeader

    // WHEN
    // The request is signed
    val signer: AwsSigner = AwsSigner(AwsCredentialsProvider, Region, Service, clock)
    val signedHeaders = signer.getSignedHeaders(Uri, GetMethod, EmptyQueryParams, headers, emptyPayload)

    // THEN
    // The signature must match the expected signature
    val expectedSignature: String = "922abe18f0e78e55d69b34458c61e73134ab710adcb9a3257b638d70e2363ce1"
    val expectedAuthorizationHeader: String = String.format("AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s", AwsAccessKey, Region, Service, expectedSignature)

    assert(signedHeaders.contains("Authorization"))
    assert(signedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(signedHeaders.contains("Host"))
    assert(signedHeaders.getOrElse("Host", "").equals(Host))
    assert(signedHeaders.contains("X-Amz-Date"))
    assert(signedHeaders.getOrElse("X-Amz-Date", "").equals(date))
    assert(!signedHeaders.contains("Date"))
  }

  it should "pass the GET vanilla test with temp credentials" in {

    // weird date : 09 Sep 2011 is a friday, not a monday
    val date = "Mon, 09 Sep 2011 23:36:00 GMT"

    // Header for HTTP Request.
    val headers = Map("Date" -> date) ++ hostHeader

    // WHEN
    // The request is signed
    val signer: AwsSigner = AwsSigner(AwsCredentialsProviderWithSession, Region, Service, clock)
    val signedHeaders = signer.getSignedHeaders(Uri, GetMethod, EmptyQueryParams, headers, emptyPayload)

    // THEN
    // The signature must match the expected signature
    val expectedSignature: String = "78448a6ffad33b798ea2bb717fe5c3ef849a1b726ed1e692f4b5635b95070fb3"
    val expectedAuthorizationHeader: String = format("AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host;x-amz-security-token, Signature=%s", AwsAccessKey, Region, Service, expectedSignature)

    assert(signedHeaders.contains("Authorization"))
    assert(signedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(signedHeaders.contains("Host"))
    assert(signedHeaders.getOrElse("Host", "").equals(Host))
    assert(signedHeaders.contains("Date"))
    assert(signedHeaders.getOrElse("Date", "").equals(date))
    assert(!signedHeaders.contains("X-Amz-Date"))
    assert(signedHeaders.contains("X-Amz-Security-Token"))
    assert(signedHeaders.getOrElse("X-Amz-Security-Token", "").equals(SessionToken))
  }
}
