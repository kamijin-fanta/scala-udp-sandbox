import java.net.{Inet4Address, InetAddress}

import model.BootpPacket.BootpDhcpExtention
import model._

import scala.concurrent.Future



class DhcpService {
  def recive(bootpPacket: BootpPacket): Future[Option[BootpPacket]] = {
    bootpPacket match  {
      case discover if discover.isDiscover =>
        println(s"===>discover $discover")

        val offer = discover.copy(
          yourClientIp = InetAddress.getByName("10.0.0.10").asInstanceOf[Inet4Address],
          bootpType = 2,
          options = DhcpOptions(
            DhcpMessageType.Offer,
            Some("255.255.255.0"),
            Some("10.0.0.1"),
            Some("8.8.8.8"),
            Some(100)).asBootpOptions
        )

        Future.successful(Some(offer))
      case request if request.isRequest =>
        println(s"===>request $request")

        val offer = request.copy(
          yourClientIp = InetAddress.getByName("10.0.0.10").asInstanceOf[Inet4Address],
          bootpType = 2,
          options = DhcpOptions(
            DhcpMessageType.Ack,
            Some("255.255.255.0"),
            Some("10.0.0.1"),
            Some("8.8.8.8"),
            Some(100)).asBootpOptions
        )

        Future.successful(Some(offer))
      case x =>
        println(s"===>known $x")
        Future.successful(None)
    }
  }
}
