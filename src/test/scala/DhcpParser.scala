import java.net.InetAddress

import fastparse.byte.all
import fastparse.byte.all.Bytes
import javax.xml.bind.DatatypeConverter
import model._
import org.scalatest.FunSpec
import scodec.bits.ByteVector

class DhcpParser extends FunSpec {
  def hexToBytes(hex: String): ByteVector = {
    ByteVector(DatatypeConverter.parseHexBinary(hex))
  }

  def getBootpOption(value: BootpPacket, optionType: Int): all.Bytes = {
    value.options.find(_.optionType == optionType).map(_.value) match {
      case Some(x) => x
      case None => fail(s"not found BootpOption type: $optionType")
    }
  }


  // udp payload
  val discover = "01010600a1290416000000000000000000000000000000000000000000ac79792a1a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013d070100ac79792a1a3204c0a86f690c0850433130333535333c084d53465420352e30370e0103060f1f212b2c2e2f7779f9fcff0000000000"


  it("discover decode & encode") {
    // 本物のパケットのパース→バイト列への変換→パースを行っている
    val result = BootpPacket.parse(hexToBytes(discover))
    val value = result.get.value

    assert(value.bootpType === 1)
    assert(value.transactionId.toHexString === "a1290416")
    assert(value.yourClientIp.getHostAddress === "0.0.0.0")
    assert(value.clientMac.toString === "00:ac:79:79:2a:1a")
    assert(getBootpOption(value, BootpOptionType.DhcpMessageType).toInt() === DhcpMessageType.Discover)
    assert(getBootpOption(value, BootpOptionType.RequestedIpAddress) === Bytes(0xc0, 0xa8, 0x6f, 0x69)) // 192.168.111.105

    val packetBytes = value.asBytes

    assert(BootpPacket.parse(packetBytes).get.value === value)
  }

  val offer = "02010600a12904160000000000000000c0a86f69000000000000000000ac79792a1a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501023604c0a86f013304000151800104ffffff000304c0a86f01060408080808ff0000000000000000000000000000000000000000000000000000"

  it("offer") {
    val result = BootpPacket.parse(hexToBytes(offer))
    val value = result.get.value

    assert(value.bootpType === 2)
    assert(getBootpOption(value, BootpOptionType.DhcpMessageType).toInt() === DhcpMessageType.Offer)
    assert(value.yourClientIp === InetAddress.getByName("192.168.111.105"))
    assert(getBootpOption(value, BootpOptionType.Router) === Bytes(0xc0, 0xa8, 0x6f, 0x01)) // 192.168.111.101
    assert(getBootpOption(value, BootpOptionType.DNS) === Bytes(0x08, 0x08, 0x08, 0x08)) // 192.168.111.101
    assert(getBootpOption(value, BootpOptionType.SubnetMask) === Bytes(0xff, 0xff, 0xff, 0x00))
    assert(getBootpOption(value, BootpOptionType.IpAddressLeaseTime).toLong() === 86400)
  }
}

