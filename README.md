**NOTE**: this project is deprecated in favor of a broader library for this and other AWS features. See here: https://github.com/aws4s/aws4s

AWS Request Signer
==================

Helper to evaluate the signing headers for HTTP requests to Amazon Web Services. This is a Scala port of (part of) the Java [aws-signing-request-interceptor](https://github.com/inreachventures/aws-signing-request-interceptor).

I originally needed this library to support AWS' [Elasticsearch Service](https://aws.amazon.com/elasticsearch-service/), but this library is 'AWS service agnostic'.


Import via SBT
--------------

Currently available for scala 2.10, 2.11 and 2.12. In your build.sbt file,

```sbt
resolvers += Resolver.jcenterRepo

libraryDependencies += "io.ticofab" %% "aws-request-signer" % "0.5.2"
```

Usage
-----

The procedure to sign AWS Api requests is described on the [official documentation](http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html). The idea is that each request must be signed through the evaluation of a hash which depends on the very request itself. The resulting string can then be added to the request either as a header or as a query param. This library focuses on the header way.

You first need to instantiate the signer, for example:

```scala
val awsCredentialProvider = new StaticCredentialsProvider(new BasicAWSCredentials("YOUR-ID", "YOUR-SECRET"))
val service = "es"
val region = "eu-central-1"
def clock(): LocalDateTime = LocalDateTime.now(ZoneId.of("UTC"))
val signer = io.ticofab.AwsSigner(awsCredentialProvider, region, service, clock)
```

Then use it for each request, via

```scala
def getSignedHeaders(uri: String,
                     method: String,
                     queryParams: Map[String, String],
                     headers: Map[String, String],
                     payload: Option[Array[Byte]]): Map[String, String]
```


Check the examples in the test folder of this project. Once you have the headers, add them to your HTTP request and fire it.

Implementations
---------------
[aws-request-signer-proxy](https://github.com/charles-rumley/aws-request-signer-proxy) implements this package as a Dockerized proxy application, and provides an example integration with the [Play framework](https://www.playframework.com/).


Dependencies
------------

* [AWS Java SDK](https://aws.amazon.com/sdk-for-java/)
* [ScalaTest](http://www.scalatest.org)

License
--------

    Copyright 2016, 2017 Fabio Tiriticco - Fabway

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
