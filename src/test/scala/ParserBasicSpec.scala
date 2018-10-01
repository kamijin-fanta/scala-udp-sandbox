import fastparse.all
import fastparse.all._
import org.scalatest.FunSpec

class ParserBasicSpec extends FunSpec {

  it("cookie") {
    val input = "yummy_cookie=choco; tasty_cookie=strawberry"

    val key = (!"=" ~ AnyChar).rep.! // "=" 以外の文字列にマッチ
    val value = (!CharIn(";", " ") ~ AnyChar).rep.!
    val field = P(key ~ "=" ~ value)
    val cookie = P(Start ~ field.rep(sep = "; ") ~ End)

    val res = cookie.parse(input).get.value
    assert(res === Seq(
      "yummy_cookie" -> "choco",
      "tasty_cookie" -> "strawberry",
    ))
  }


  object Json {

    // like: type JsonExpr = JsObject | JsArray | JsNumber | JsBoolean | JsString | JsNull
    sealed trait JsonExpr

    case class JsObject(obj: Map[String, JsonExpr]) extends JsonExpr

    case class JsArray(values: Seq[JsonExpr]) extends JsonExpr

    case class JsBoolean(value: Boolean) extends JsonExpr

    case class JsNumber(value: Int) extends JsonExpr

    case class JsString(value: String) extends JsonExpr

    case object JsNull extends JsonExpr

  }

  object JsonParser {
    import Json._

    val space = CharsWhileIn(" \r\n").rep // 空白のいずれかにマッチ
    val char = (!CharIn("\"\\") ~ AnyChar).!  // "\ 以外の文字列にマッチ
    val chars = space ~ "\"" ~ char.rep.! ~ "\"" ~ space  // ""に囲まれた文字列
    val digit = CharIn('0' to '9').!

    val boolTrue = P("true").map(_ => JsBoolean(true))
    val boolFalse = P("false").map(_ => JsBoolean(false))
    val bool = boolTrue | boolFalse

    val string = chars.map(s => JsString(s))
    val nul = P("null").map(_ => JsNull)
    val number = P(CharIn("+-").? ~ digit.rep(min=1)).!.map(v => JsNumber(v.toInt))

    val objPare = P(chars ~/ ":" ~/ json)
    val obj = P("{" ~/ objPare.rep(sep = ",".~/) ~/ "}").map(s => JsObject(s.toMap))

    val array = P("[" ~/ json.rep(sep = ",".~/) ~/ "]").map(s => JsArray(s))

    val json: all.Parser[JsonExpr] =
      P(space ~ (obj | string | array | nul | number | bool) ~ space)
  }

  it("json") {
    import Json._
    val input = """ { "text": "value", "array": [null, 1234, "str"]} """

    val res = JsonParser.json.parse(input)
    assert(res.get.value ===
      JsObject(Map(
        "text" -> JsString("value"),
        "array" -> JsArray(List(JsNull, JsNumber(1234), JsString("str"))),
      ))
    )

    val failure @ Parsed.Failure(_, _, _) =
      JsonParser.json.parse(""" {"key": [null, FOOO]} """)
    assert(failure.msg === """(obj | CharsWhileIn(" \r\n").rep ~ "\"" ~ !(CharIn("\"\\")) ~ AnyChar.rep ~ "\"" ~ CharsWhileIn(" \r\n").rep | array | nul | number):1:17 ..."FOOO]} """")
  }
}
