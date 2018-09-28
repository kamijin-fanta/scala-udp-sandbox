import org.scalatest.FunSpec

import fastparse.all._

class CookieParser extends FunSpec {

  it("cookie") {
    val input = "yummy_cookie=choco; tasty_cookie=strawberry"

    val key = AnyChar.rep
    val value = AnyChar.rep
    val field = P(Start ~ key)

    val res = field.parse(input)
    println(res)
  }
}
