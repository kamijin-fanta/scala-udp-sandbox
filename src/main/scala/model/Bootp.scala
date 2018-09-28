package model

import java.net.{Inet4Address, InetAddress}
import java.nio.ByteBuffer

import fastparse.byte.all
import fastparse.byte.all.Bytes
import fastparse.core
import fastparse.core.Parsed.Success
import org.pcap4j.util.{ByteArrays, MacAddress}

object BootpPacket {

  import fastparse.byte.all._
  import BE._

  val parser: core.Parser[BootpPacket, Byte, all.Bytes] = P(
    // bootpType  eth    addrLen    Hops     Trans
    UInt8 ~ BS(0x01, 0x06) ~ AnyByte ~ UInt32 ~ AnyBytes(8) ~
      // ip                         mac address
      AnyBytes(4).! ~ AnyBytes(8) ~ UInt8.rep(exactly = 6) ~ AnyBytes(10) ~

      // ServerHostName     BootFileName           Magic Cookie
      AnyBytes(64) ~ AnyBytes(128) ~ AnyBytes(4) ~

      // options type(1) length(1) value(n)
      (Int8.filter(_ != -1) ~ Int8.flatMap(size => AnyBytes(size).!))
        .map(x => BootpOption(x._1, x._2))
        .rep ~

      // option end
      BS(0xff)
  ).map(x => {
    BootpPacket(
      bootpType = x._1,
      transactionId = x._2,
      yourClientIp = ByteArrays.getInet4Address(x._3.toArray, 0),
      clientMac = MacAddress.getByAddress(x._4.map(_.toByte).toArray),
      options = x._5
    )
  })

  def parse(byteBuffer: ByteBuffer): core.Parsed[BootpPacket, Byte, all.Bytes] = {
    val arr = new Array[Byte](byteBuffer.remaining())
    byteBuffer.get(arr)
    parse(arr)
  }

  def parse(array: Array[Byte]): core.Parsed[BootpPacket, Byte, all.Bytes] =
    parse(Bytes(array))

  def parse(bytes: Bytes): core.Parsed[BootpPacket, Byte, all.Bytes] =
    parser.parse(bytes)

  def parseOpt(array: Array[Byte]): Option[BootpPacket] =
    parse(array) match {
      case Success(x, index) =>
        Some(x)
      case _ =>
        None
    }

  implicit class BootpDhcpExtention(value: BootpPacket) {
    private val messageType = {
      value.options
        .find(_.optionType == BootpOptionType.DhcpMessageType)
        .map(_.value.toInt())
        .getOrElse(0)
    }

    def isDiscover: Boolean = value.bootpType == 1 && messageType == DhcpMessageType.Discover
    def isOffer: Boolean = value.bootpType == 2 && messageType == DhcpMessageType.Offer
    def isRequest: Boolean = value.bootpType == 1 && messageType == DhcpMessageType.Request
    def isAck: Boolean = value.bootpType == 2 && messageType == DhcpMessageType.Ack
  }

}

case class BootpPacket(
                        bootpType: Short,
                        transactionId: Long,
                        yourClientIp: Inet4Address,
                        clientMac: MacAddress,
                        options: Seq[BootpOption]) {

  def asBytes: Bytes =
    Bytes(bootpType) ++ Bytes(0x01, 0x06, 0) ++
      Bytes.fromLong(transactionId, size = 4) ++ Bytes.fill(8)(0) ++
      Bytes(yourClientIp.getAddress) ++ Bytes.fill(8)(0) ++
      Bytes(clientMac.getAddress) ++ Bytes.fill(10)(0) ++
      Bytes.fill(64)(0) ++ Bytes.fill(128)(0) ++ Bytes(0x63, 0x82, 0x53, 0x63) ++
      Bytes.concat(options.map(o => Bytes(o.optionType) ++ Bytes.fromLong(o.value.length, 1) ++ o.value)) ++
      Bytes(0xff)

}

case class DhcpOptions(
                        messageType: Int,
                        mask: Option[String],
                        router: Option[String],
                        dns: Option[String],
                        leaseTime: Option[Int]
                      ) {
  def asBootpOptions: Seq[BootpOption] = {
    Seq(
      BootpOption(BootpOptionType.DhcpMessageType, Bytes(messageType))
    ) ++ mask.map(m =>
      BootpOption(BootpOptionType.SubnetMask, Bytes(InetAddress.getByName(m).getAddress))
    ) ++ router.toSeq.flatMap(r =>
      Seq(
        BootpOption(BootpOptionType.Router, Bytes(InetAddress.getByName(r).getAddress)),
        BootpOption(BootpOptionType.DhcpServerIdentify, Bytes(InetAddress.getByName(r).getAddress))
      )
    ) ++ dns.map(d =>
      BootpOption(BootpOptionType.DNS, Bytes(InetAddress.getByName(d).getAddress))
    ) ++ leaseTime.map(l =>
      BootpOption(BootpOptionType.IpAddressLeaseTime, Bytes.fromInt(l))
    )
  }
}


case class BootpOption(optionType: Short, value: Bytes)

object BootpOptionType extends Enumeration {
  val SubnetMask = 1.toShort
  val Router = 3.toShort
  val DNS = 6.toShort
  val HostName = 12.toShort
  val RequestedIpAddress = 50.toShort
  val IpAddressLeaseTime = 51.toShort
  val DhcpMessageType = 53.toShort
  val DhcpServerIdentify = 54.toShort
  val ParameterRequestList = 55.toShort
}

object DhcpMessageType extends Enumeration {
  val Discover = 1
  val Offer = 2
  val Request = 3
  val Ack = 5
  val Release = 7
}
