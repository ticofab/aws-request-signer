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
  val Service = "host"

  // Test Credentials for testing with session token.
  val SessionToken: String = "AKIDEXAMPLESESSION"
  val CredentialsWithSession: AWSCredentials = new BasicSessionCredentials(AwsAccessKey, AwsSecretKey, SessionToken)
  val AwsCredentialsProviderWithSession: AWSCredentialsProvider = new AWSStaticCredentialsProvider(CredentialsWithSession)

  // Test Credentials using profile for testing with session token.
  val ProfileCredentialsWithSession: AWSCredentials = new ProfileCredentialsProvider(System.getProperty("user.home")+ "/.aws/credentials","default").getCredentials()
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

  /**
    * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
    * (get-vanilla.*)
    *
    * GET / http/1.1
    * Date:Mon, 09 Sep 2011 23:36:00 GMT
    * Host:host.foo.com
    *
    */
  "AwsSigner" should "pass the GET vanilla test" in {

    // DATE
    // weird date : 09 Sep 2011 is a friday, not a monday
    val date = "Mon, 09 Sep 2011 23:36:00 GMT"

    // Header for HTTP Request.
    val headers: Map[String, String] = Map("Date" -> date) ++ hostHeader

    val signer: AwsSigner = AwsSigner(AwsCredentialsProvider, Region, Service, clock)
    val signedHeaders = signer.getSignedHeaders(Uri, GetMethod, EmptyQueryParams, headers, emptyPayload)

    // The signature must match the expected signature
    val expectedSignature = "b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470"
    val expectedAuthorizationHeader = String.format(
      "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
      AwsAccessKey, Region, Service, expectedSignature
    )

    val caseInsensitiveSignedHeaders = signedHeaders
    assert(caseInsensitiveSignedHeaders.contains("Authorization"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(caseInsensitiveSignedHeaders.contains("Host"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Host", "").equals(Host))
    assert(caseInsensitiveSignedHeaders.contains("Date"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Date", "").equals(date))
    assert(!caseInsensitiveSignedHeaders.contains("X-Amz-Date"))
  }

  /**
    * Test case given in AWS Signing Test Suite (http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)
    * (post-vanilla-query.*)
    *
    * POST /?foo=bar http/1.1
    * Date:Mon, 09 Sep 2011 23:36:00 GMT
    * Host:host.foo.com
    *
    */
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
    val expectedSignature: String = "b6e3b79003ce0743a491606ba1035a804593b0efb1e20a11cba83f8c25a57a92"
    val expectedAuthorizationHeader: String = format("AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s", AwsAccessKey, Region, Service, expectedSignature)

    val caseInsensitiveSignedHeaders = signedHeaders
    assert(caseInsensitiveSignedHeaders.contains("Authorization"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(caseInsensitiveSignedHeaders.contains("Host"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Host", "").equals(Host))
    assert(caseInsensitiveSignedHeaders.contains("Date"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Date", "").equals(date))
    assert(!caseInsensitiveSignedHeaders.contains("X-Amz-Date"))
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
    val expectedSignature: String = "904f8c568bca8bd2618b9241a7f2a8d90f279e717fd0f6727af189668b040151"
    val expectedAuthorizationHeader: String = String.format("AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s", AwsAccessKey, Region, Service, expectedSignature)

    val caseInsensitiveSignedHeaders = signedHeaders
    assert(caseInsensitiveSignedHeaders.contains("Authorization"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(caseInsensitiveSignedHeaders.contains("Host"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Host", "").equals(Host))
    assert(caseInsensitiveSignedHeaders.contains("X-Amz-Date"))
    assert(caseInsensitiveSignedHeaders.getOrElse("X-Amz-Date", "").equals(date))
    assert(!caseInsensitiveSignedHeaders.contains("Date"))
  }

  // TODO: ignoring this test as the session token is not implemented yet
  ignore should "pass the GET vanilla test with temp credentials" in {

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
    val expectedSignature: String = "43abd9e63c148feb91c43fe2c9734eb44b7eb16078d484d3ff9b6249b62fdc60"
    val expectedAuthorizationHeader: String = format("AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host;x-amz-security-token, Signature=%s", AwsAccessKey, Region, Service, expectedSignature)

    val caseInsensitiveSignedHeaders = signedHeaders
    assert(caseInsensitiveSignedHeaders.contains("Authorization"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(caseInsensitiveSignedHeaders.contains("Host"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Host", "").equals(Host))
    assert(caseInsensitiveSignedHeaders.contains("Date"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Date", "").equals(date))
    assert(!caseInsensitiveSignedHeaders.contains("X-Amz-Date"))
    assert(caseInsensitiveSignedHeaders.contains("X-Amz-Security-Token"))
    assert(caseInsensitiveSignedHeaders.getOrElse("X-Amz-Security-Token", "").equals(SessionToken))
  }
}
