package io.ticofab

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.{InvalidKeyException, MessageDigest, NoSuchAlgorithmException}
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import com.amazonaws.auth.{AWSCredentials, AWSCredentialsProvider}
import org.apache.commons.codec.binary.Hex
import org.joda.time.DateTime
import org.joda.time.format.{DateTimeFormat, ISODateTimeFormat}

import scala.collection.mutable

/**
  * Inspired By: https://github.com/inreachventures/aws-signing-request-interceptor
  */
case class AwsSigner(credentialsProvider: AWSCredentialsProvider,
                     region: String,
                     service: String,
                     clock: () => DateTime) {

  val BASE16MAP = Array[Char]('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
  val HMAC_SHA256 = "HmacSHA256"
  val SLASH = "/"
  val X_AMZ_DATE = "x-amz-date"
  val RETURN = "\n"
  val AWS4_HMAC_SHA256 = "AWS4-HMAC-SHA256\n"
  val AWS4_REQUEST = "/aws4_request"
  val AWS4_HMAC_SHA256_CREDENTIAL = "AWS4-HMAC-SHA256 Credential="
  val SIGNED_HEADERS = ", SignedHeaders="
  val SIGNATURE = ", Signature="
  val SHA_256 = "SHA-256"
  val AWS4 = "AWS4"
  val AWS_4_REQUEST = "aws4_request"
  val CONNECTION = "connection"
  val CLOSE = ":close"
  val EMPTY = ""
  val ZERO = "0"
  val CONTENT_LENGTH = "Content-Length"
  val AUTHORIZATION = "Authorization"
  val SESSION_TOKEN = "x-amz-security-token"
  val DATE = "date"
  val DATE_FORMATTER = DateTimeFormat.forPattern("yyyyMMdd'T'HHmmss'Z'")

  def getSignedHeaders(uri: String,
                       method: String,
                       queryParams: Map[String, String],
                       headers: Map[String, Object],
                       payload: Option[Array[Byte]]): Map[String, String] = {
    val now: DateTime = clock.apply()
    val credentials: AWSCredentials = credentialsProvider.getCredentials

    var result = mutable.Map[String, Object]()
    for ((key, value) <- headers) result += key -> value

    if (!result.contains(DATE)) {
      result += (X_AMZ_DATE -> now.toString(DATE_FORMATTER))
    }

    // TODO
    //    if (AWSSessionCredentials.class.isAssignableFrom(credentials.getClass()))
    //    {
    //      result.put(SESSION_TOKEN, ((AWSSessionCredentials) credentials).getSessionToken());
    //    }

    val headersString: String = result.toMap.map(pair => headerAsString(pair) + RETURN).mkString
    val signedHeaders: List[String] = result.toMap.map(pair => pair._1.toLowerCase).toList

    val signedHeaderKeys = signedHeaders.mkString(";")
    val canonicalRequest = method + RETURN +
      uri + RETURN +
      queryParamsString(queryParams) + RETURN +
      headersString + RETURN +
      signedHeaderKeys + RETURN +
      toBase16(payload.getOrElse(EMPTY.getBytes(StandardCharsets.UTF_8)))

    val stringToSign = createStringToSign(canonicalRequest, now)
    val signature = sign(stringToSign, now, credentials)
    val autorizationHeader = AWS4_HMAC_SHA256_CREDENTIAL +
      credentials.getAWSAccessKeyId + SLASH + getCredentialScope(now) +
      SIGNED_HEADERS + signedHeaderKeys +
      SIGNATURE + signature

    result += (AUTHORIZATION -> autorizationHeader)

    result.mapValues(_.toString).toMap
  }

  private def queryParamsString(queryParams: Map[String, String]) =
    queryParams.map(pair => pair._1 + "=" + URLEncoder.encode(pair._2, "UTF-8")).mkString("&")

  private def headerAsString(header: (String, Object)): String = {
    if (header._1.equalsIgnoreCase(CONNECTION)) {
      CONNECTION + CLOSE
    } else if (header._1.equalsIgnoreCase(CONTENT_LENGTH) && header._2.equals(ZERO)) {
      header._1.toLowerCase() + ':'
    } else {
      header._1.toLowerCase() + ':' + header._2
    }
  }

  private def sign(stringToSign: String, now: DateTime, credentials: AWSCredentials): String = {
    Hex.encodeHexString(hmacSHA256(stringToSign, getSignatureKey(now, credentials)))
  }

  private def createStringToSign(canonicalRequest: String, now: DateTime): String = {
    AWS4_HMAC_SHA256 +
      now.toString(DATE_FORMATTER) + RETURN +
      getCredentialScope(now) + RETURN +
      toBase16(hash(canonicalRequest.getBytes(StandardCharsets.UTF_8)))
  }

  private def getCredentialScope(now: DateTime): String = {
    now.toString(ISODateTimeFormat.basicDate()) + SLASH + region + SLASH + service + AWS4_REQUEST
  }

  private def hash(payload: Array[Byte]): Array[Byte] = {
    try {
      val md: MessageDigest = MessageDigest.getInstance(SHA_256)
      md.update(payload)
      md.digest
    } catch {
      case n: NoSuchAlgorithmException => throw n
    }
  }

  private def toBase16(data: Array[Byte]): String = {
    data.map(byte => (BASE16MAP(byte >> 4 & 0xF), BASE16MAP(byte & 0xF))).toList.flatMap(pair => List(pair._1, pair._2)).mkString
  }

  private def getSignatureKey(now: DateTime, credentials: AWSCredentials): Array[Byte] = {
    val kSecret: Array[Byte] = (AWS4 + credentials.getAWSSecretKey).getBytes(StandardCharsets.UTF_8)
    val kDate: Array[Byte] = hmacSHA256(now.toString(DATE_FORMATTER), kSecret)
    val kRegion: Array[Byte] = hmacSHA256(region, kDate)
    val kService: Array[Byte] = hmacSHA256(service, kRegion)
    hmacSHA256(AWS_4_REQUEST, kService)
  }

  private def hmacSHA256(data: String, key: Array[Byte]): Array[Byte] = {
    try {
      val mac: Mac = Mac.getInstance(HMAC_SHA256)
      mac.init(new SecretKeySpec(key, HMAC_SHA256))
      mac.doFinal(data.getBytes(StandardCharsets.UTF_8))
    } catch {
      case e: NoSuchAlgorithmException => throw e
      case i: InvalidKeyException => throw i
    }
  }

}