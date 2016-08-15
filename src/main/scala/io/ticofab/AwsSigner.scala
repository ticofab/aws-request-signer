package io.ticofab

/**
  * Copyright 2015 Fabio Tiriticco, Fabway
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  * http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.{InvalidKeyException, MessageDigest, NoSuchAlgorithmException}
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import com.amazonaws.auth.{AWSCredentials, AWSCredentialsProvider}
import org.apache.commons.codec.binary.Hex

import scala.collection.immutable.TreeMap

/**
  * Inspired By: https://github.com/inreachventures/aws-signing-request-interceptor
  */
case class AwsSigner(credentialsProvider: AWSCredentialsProvider,
                     region: String,
                     service: String,
                     clock: () => LocalDateTime) {

  val BASE16MAP = Array[Char]('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
  val HMAC_SHA256 = "HmacSHA256"
  val SLASH = "/"
  val X_AMZ_DATE = "x-amz-date"
  val RETURN = "\n"
  val AWS4_HMAC_SHA256 = "AWS4-HMAC-SHA256"
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
  val DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
  val BASIC_DATE_FORMATTER = DateTimeFormatter.BASIC_ISO_DATE

  def getSignedHeaders(uri: String,
                       method: String,
                       queryParams: Map[String, String],
                       headers: Map[String, String],
                       payload: Option[Array[Byte]]): Map[String, String] = {

    def queryParamsString(queryParams: Map[String, String]) =
      queryParams.map(pair => pair._1 + "=" + URLEncoder.encode(pair._2, "UTF-8")).mkString("&")

    def sign(stringToSign: String, now: LocalDateTime, credentials: AWSCredentials): String = {
      def hmacSHA256(data: String, key: Array[Byte]): Array[Byte] = {
        try {
          val mac: Mac = Mac.getInstance(HMAC_SHA256)
          mac.init(new SecretKeySpec(key, HMAC_SHA256))
          mac.doFinal(data.getBytes(StandardCharsets.UTF_8))
        } catch {
          case e: NoSuchAlgorithmException => throw e
          case i: InvalidKeyException => throw i
        }
      }

      def getSignatureKey(now: LocalDateTime, credentials: AWSCredentials): Array[Byte] = {
        val kSecret: Array[Byte] = (AWS4 + credentials.getAWSSecretKey).getBytes(StandardCharsets.UTF_8)
        val kDate: Array[Byte] = hmacSHA256(now.format(BASIC_DATE_FORMATTER), kSecret)
        val kRegion: Array[Byte] = hmacSHA256(region, kDate)
        val kService: Array[Byte] = hmacSHA256(service, kRegion)
        hmacSHA256(AWS_4_REQUEST, kService)
      }

      Hex.encodeHexString(hmacSHA256(stringToSign, getSignatureKey(now, credentials)))
    }

    def headerAsString(header: (String, Object)): String =
      if (header._1.equalsIgnoreCase(CONNECTION)) {
        CONNECTION + CLOSE
      } else if (header._1.equalsIgnoreCase(CONTENT_LENGTH) && header._2.equals(ZERO)) {
        header._1.toLowerCase + ':'
      } else {
        header._1.toLowerCase + ':' + header._2
      }

    def getCredentialScope(now: LocalDateTime): String =
      now.format(BASIC_DATE_FORMATTER) + SLASH + region + SLASH + service + AWS4_REQUEST

    def hash(payload: Array[Byte]): Array[Byte] =
      try {
        val md: MessageDigest = MessageDigest.getInstance(SHA_256)
        md.update(payload)
        md.digest
      } catch {
        case n: NoSuchAlgorithmException => throw n
      }

    def toBase16(data: Array[Byte]): String =
      data.map(byte => (BASE16MAP(byte >> 4 & 0xF), BASE16MAP(byte & 0xF))).toList.flatMap(pair => List(pair._1, pair._2)).mkString

    def createStringToSign(canonicalRequest: String, now: LocalDateTime): String =
      AWS4_HMAC_SHA256 + RETURN +
        now.format(DATE_FORMATTER) + RETURN +
        getCredentialScope(now) + RETURN +
        toBase16(hash(canonicalRequest.getBytes(StandardCharsets.UTF_8)))

    // evaluate current time from the provided clock
    val now: LocalDateTime = clock.apply()

    // signing credentials
    val credentials: AWSCredentials = credentialsProvider.getCredentials

    var result = TreeMap[String, String]()(Ordering.by(_.toLowerCase))
    for ((key, value) <- headers) result += key -> value

    if (!result.contains(DATE)) {
      result += (X_AMZ_DATE -> now.format(DATE_FORMATTER))
    }

    // TODO
    //    if (AWSSessionCredentials.class.isAssignableFrom(credentials.getClass()))
    //    {
    //      result.put(SESSION_TOKEN, ((AWSSessionCredentials) credentials).getSessionToken());
    //    }

    val headersString: String = result.toMap.map(pair => headerAsString(pair) + RETURN).mkString
    val signedHeaders: List[String] = result.toMap.map(pair => pair._1.toLowerCase).toList

    val signedHeaderKeys = signedHeaders.mkString(";")
    val canonicalRequest =
      method + RETURN +
      uri + RETURN +
      queryParamsString(queryParams) + RETURN +
      headersString + RETURN +
      signedHeaderKeys + RETURN +
      toBase16(hash(payload.getOrElse(EMPTY.getBytes(StandardCharsets.UTF_8))))

    val stringToSign = createStringToSign(canonicalRequest, now)
    val signature = sign(stringToSign, now, credentials)
    val authorizationHeader = AWS4_HMAC_SHA256_CREDENTIAL +
      credentials.getAWSAccessKeyId + SLASH + getCredentialScope(now) +
      SIGNED_HEADERS + signedHeaderKeys +
      SIGNATURE + signature

    result += (AUTHORIZATION -> authorizationHeader)

    result.toMap
  }
}
