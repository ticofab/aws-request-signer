name := """aws-request-signer"""

organization := "io.ticofab"

licenses += ("The Apache Software License, Version 2.0", url("http://www.apache.org/licenses/LICENSE-2.0.txt"))

javacOptions ++= Seq("-source", "1.8", "-target", "1.8")

scalaVersion := "2.11.7"

crossScalaVersions := Seq("2.10.6", "2.11.7")

libraryDependencies ++= Seq(

  // test framework
  "org.scalatest" %% "scalatest" % "2.2.4" % "test",

  "com.amazonaws" % "aws-java-sdk-core" % "1.10.19"

)

com.typesafe.sbt.SbtGit.versionWithGit
