package io.ticofab

case class AccessKeyID(value: String) extends AnyVal

case class SecretAccessKey(value: String) extends AnyVal

case class AwsCredentials(accessKeyID: AccessKeyID, secretAccessKey: SecretAccessKey)