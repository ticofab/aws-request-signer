name := """aws-request-signer"""

organization := "io.ticofab"

version := "0.2.0"

licenses += ("Apache-2.0", url("http://www.apache.org/licenses/LICENSE-2.0.txt"))

javacOptions ++= Seq("-source", "1.8", "-target", "1.8")

scalaVersion := "2.11.8"

crossScalaVersions := Seq("2.10.6", "2.11.7", "2.11.8")

libraryDependencies ++= Seq(

  // test framework
  "org.scalatest" %% "scalatest" % "3.0.0" % "test",

  // aws java SDK
  "com.amazonaws" % "aws-java-sdk-core" % "1.11.51"

)

bintrayPackageLabels := Seq("scala", "aws")

com.typesafe.sbt.SbtGit.versionWithGit
