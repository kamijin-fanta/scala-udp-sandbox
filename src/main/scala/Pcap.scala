import java.net.InetAddress
import java.util.concurrent.{ExecutorService, Executors}

import org.pcap4j.core.BpfProgram.BpfCompileMode
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode
import org.pcap4j.core.{PacketListener, Pcaps}
import org.pcap4j.packet.{EthernetPacket, IpV4Packet, Packet, UdpPacket}

import scala.concurrent.{ExecutionContext, Future}
import scala.io.StdIn

object Pcap {
  def main(args: Array[String]): Unit = {
    val addr = InetAddress.getByName("192.168.111.105")
    val nif = Pcaps.getDevByAddress(addr)

    val snapLen = 65536
    val mode = PromiscuousMode.PROMISCUOUS
    val timeout = 10
    val handle = nif.openLive(snapLen, mode, timeout)
    handle.setFilter("broadcast", BpfCompileMode.OPTIMIZE)

    val executorService: ExecutorService = Executors.newCachedThreadPool()
    val ex = ExecutionContext.fromExecutor(executorService)

    Future {
      try {
        handle.loop(-1, new PacketListener {
          override def gotPacket(packet: Packet): Unit = handlePacket(packet)
        })
      } catch {
        case th: InterruptedException => ()
        case th: Throwable => throw th
      }
    }(ex)
    println("-------------")

    StdIn.readLine()
    println("===========close===========")
    if (handle.isOpen) {
      handle.breakLoop()
      handle.close()
    }
    executorService.shutdown()
  }


  def handlePacket(packet: Packet) = packet match {
    case eth: EthernetPacket =>
      println(s"Ethernet ${eth.getHeader.getSrcAddr} -> ${eth.getHeader.getDstAddr}")
      eth.getPayload match {
        case v4: IpV4Packet =>
          println(s"  IPv4 ${v4.getHeader.getSrcAddr} -> ${v4.getHeader.getDstAddr}")
          v4.getPayload match {
            case udp: UdpPacket =>
              println(s"    UDP ${udp.getHeader.getSrcPort} -> ${udp.getHeader.getDstPort}")
              if (udp.getHeader.getDstPort.valueAsInt() == 67) {
                println("===============================================    DHCP")
              }
          }
      }
    case x =>
      println("other packet")
    //            println(x)
  }
}
