package io.ticofab

import io.ticofab.Foo
import org.scalatest.{WordSpec, MustMatchers}

class FooSpec extends WordSpec with MustMatchers {

  object Foo extends Foo

  "Foo" must {
    "say hello" in {
      Foo.hello("bar") must equal ("hello, bar")
    }
  }

}