package io.ticofab

import java.lang.String._
import java.time.LocalDateTime

import com.amazonaws.auth.{AWSCredentials, AWSCredentialsProvider, BasicAWSCredentials, BasicSessionCredentials}
import com.amazonaws.internal.StaticCredentialsProvider
import org.scalatest.{FlatSpec, Matchers}

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
  "AwsSigner" should "pass the GET vanilla test" in {

    // GIVEN
    // Credentials
    val awsAccessKey = "AKIDEXAMPLE"
    val awsSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    val credentials: AWSCredentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey)
    val awsCredentialsProvider: AWSCredentialsProvider = new StaticCredentialsProvider(credentials)
    val region = "us-east-1"
    val service = "host"

    // DATE
    def clock(): LocalDateTime = LocalDateTime.of(2011, 9, 9, 23, 36, 0)
    // weird date : 09 Sep 2011 is a friday, not a monday
    val date = "Mon, 09 Sep 2011 23:36:00 GMT"

    val host = "host.foo.com"
    val uri = "/"
    val method = "GET"
    val queryParams = Map[String, String]()
    val headers: Map[String, String] = Map("Date" -> date, "Host" -> host)
    val payload: Option[Array[Byte]] = None

    val signer: AwsSigner = AwsSigner(awsCredentialsProvider, region, service, clock)
    val signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload)

    // The signature must match the expected signature
    val expectedSignature = "b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470"
    val expectedAuthorizationHeader = String.format(
      "AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s",
      awsAccessKey, region, service, expectedSignature
    )

    val caseInsensitiveSignedHeaders = signedHeaders
    assert(caseInsensitiveSignedHeaders.contains("Authorization"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(caseInsensitiveSignedHeaders.contains("Host"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Host", "").equals(host))
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
    // GIVEN
    // Credentials
    val awsAccessKey: String = "AKIDEXAMPLE"
    val awsSecretKey: String = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    val credentials: AWSCredentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey)
    val awsCredentialsProvider: AWSCredentialsProvider = new StaticCredentialsProvider(credentials)
    val region: String = "us-east-1"
    val service: String = "host"

    // Date
    def clock(): LocalDateTime = LocalDateTime.of(2011, 9, 9, 23, 36, 0)
    // weird date : 09 Sep 2011 is a friday, not a monday
    val date = "Mon, 09 Sep 2011 23:36:00 GMT"

    // HTTP request
    val host: String = "host.foo.com"
    val uri: String = "/"
    val method: String = "POST"
    val queryParams: Map[String, String] = Map("foo" -> "bar")
    val headers: Map[String, String] = Map("Date" -> date, "Host" -> host)
    val payload: Option[Array[Byte]] = None

    // WHEN
    // The request is signed
    val signer: AwsSigner = AwsSigner(awsCredentialsProvider, region, service, clock)
    val signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload)

    // THEN
    // The signature must match the expected signature
    val expectedSignature: String = "b6e3b79003ce0743a491606ba1035a804593b0efb1e20a11cba83f8c25a57a92"
    val expectedAuthorizationHeader: String = format("AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host, Signature=%s", awsAccessKey, region, service, expectedSignature)

    val caseInsensitiveSignedHeaders = signedHeaders
    assert(caseInsensitiveSignedHeaders.contains("Authorization"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(caseInsensitiveSignedHeaders.contains("Host"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Host", "").equals(host))
    assert(caseInsensitiveSignedHeaders.contains("Date"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Date", "").equals(date))
    assert(!caseInsensitiveSignedHeaders.contains("X-Amz-Date"))
  }

  it should "pass the GET vanilla test without Date Header" in {
    // GIVEN
    // Credentials
    val awsAccessKey: String = "AKIDEXAMPLE"
    val awsSecretKey: String = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    val credentials: AWSCredentials = new BasicAWSCredentials(awsAccessKey, awsSecretKey)
    val awsCredentialsProvider: AWSCredentialsProvider = new StaticCredentialsProvider(credentials)
    val region: String = "us-east-1"
    val service: String = "host"

    // Date
    def clock(): LocalDateTime = LocalDateTime.of(2011, 9, 9, 23, 36, 0)
    // weird date : 09 Sep 2011 is a friday, not a monday
    val date: String = "20110909T233600Z"

    // HTTP request
    val host: String = "host.foo.com"
    val uri: String = "/"
    val method: String = "GET"
    val queryParams: Map[String, String] = Map[String, String]()
    val headers: Map[String, String] = Map("Host" -> host)
    val payload: Option[Array[Byte]] = None

    // WHEN
    // The request is signed
    val signer: AwsSigner = AwsSigner(awsCredentialsProvider, region, service, clock)
    val signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload)

    // THEN
    // The signature must match the expected signature
    val expectedSignature: String = "904f8c568bca8bd2618b9241a7f2a8d90f279e717fd0f6727af189668b040151"
    val expectedAuthorizationHeader: String = String.format("AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s", awsAccessKey, region, service, expectedSignature)

    val caseInsensitiveSignedHeaders = signedHeaders
    assert(caseInsensitiveSignedHeaders.contains("Authorization"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(caseInsensitiveSignedHeaders.contains("Host"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Host", "").equals(host))
    assert(caseInsensitiveSignedHeaders.contains("X-Amz-Date"))
    assert(caseInsensitiveSignedHeaders.getOrElse("X-Amz-Date", "").equals(date))
    assert(!caseInsensitiveSignedHeaders.contains("Date"))
  }

  // TODO: ignoring this test as the session token is not implemented yet
  ignore should "pass the GET vanilla test with temp credentials" in {
    // GIVEN
    // Credentials
    val awsAccessKey: String = "AKIDEXAMPLE"
    val awsSecretKey: String = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    val sessionToken: String = "AKIDEXAMPLESESSION"
    val credentials: AWSCredentials = new BasicSessionCredentials(awsAccessKey, awsSecretKey, sessionToken)
    val awsCredentialsProvider: AWSCredentialsProvider = new StaticCredentialsProvider(credentials)
    val region: String = "us-east-1"
    val service: String = "host"

    // Date
    def clock(): LocalDateTime = LocalDateTime.of(2011, 9, 9, 23, 36, 0)
    // weird date : 09 Sep 2011 is a friday, not a monday
    val date = "Mon, 09 Sep 2011 23:36:00 GMT"

    // HTTP request
    val host: String = "host.foo.com"
    val uri: String = "/"
    val method: String = "GET"
    val queryParams = Map[String, String]()
    val headers = Map("Date" -> date, "Host" -> host)
    val payload: Option[Array[Byte]] = None

    // WHEN
    // The request is signed
    val signer: AwsSigner = AwsSigner(awsCredentialsProvider, region, service, clock)
    val signedHeaders = signer.getSignedHeaders(uri, method, queryParams, headers, payload)

    // THEN
    // The signature must match the expected signature
    val expectedSignature: String = "43abd9e63c148feb91c43fe2c9734eb44b7eb16078d484d3ff9b6249b62fdc60"
    val expectedAuthorizationHeader: String = format("AWS4-HMAC-SHA256 Credential=%s/20110909/%s/%s/aws4_request, SignedHeaders=date;host;x-amz-security-token, Signature=%s", awsAccessKey, region, service, expectedSignature)

    val caseInsensitiveSignedHeaders = signedHeaders
    assert(caseInsensitiveSignedHeaders.contains("Authorization"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Authorization", "").equals(expectedAuthorizationHeader))
    assert(caseInsensitiveSignedHeaders.contains("Host"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Host", "").equals(host))
    assert(caseInsensitiveSignedHeaders.contains("Date"))
    assert(caseInsensitiveSignedHeaders.getOrElse("Date", "").equals(date))
    assert(!caseInsensitiveSignedHeaders.contains("X-Amz-Date"))
    assert(caseInsensitiveSignedHeaders.contains("X-Amz-Security-Token"))
    assert(caseInsensitiveSignedHeaders.getOrElse("X-Amz-Security-Token", "").equals(sessionToken))
  }
}
