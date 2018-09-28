import java.net.{Inet4Address, InetAddress}
import java.util.concurrent.{ExecutorService, Executors}

import fastparse.byte.all.Bytes
import model.BootpPacket
import org.pcap4j.core.BpfProgram.BpfCompileMode
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode
import org.pcap4j.core.{PacketListener, PcapHandle, PcapNetworkInterface, Pcaps}
import org.pcap4j.packet._
import org.pcap4j.packet.namednumber.{EtherType, IpNumber, IpVersion, UdpPort}
import org.pcap4j.util.MacAddress

import scala.collection.JavaConverters._
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.{ExecutionContext, Future}
import scala.io.StdIn
import scala.util.{Failure, Success}

object Pcap {
  def main(args: Array[String]): Unit = {
    val deviceName = args.toList.headOption.getOrElse("")
    val deviceList = Pcaps.findAllDevs().asScala.toList

    println(s"===== DeviceList (${deviceList.length} devices) =====")
    deviceList.foreach(dev => {
      if (dev.getName == deviceName) print("> ")
      else print("  ")
      println(dev)
    })
    println()

    val nif: PcapNetworkInterface = Pcaps.getDevByName(deviceName)
    if (nif == null) {
      println("need device name in args")
    }
    val selfMac = MacAddress.getByName("fe:00:00:00:00:01")


    val dhcpService = new DhcpService

    val snapLen = 65536
    val mode = PromiscuousMode.PROMISCUOUS
    val timeout = 10
    val handle: PcapHandle = nif.openLive(snapLen, mode, timeout)
    handle.setFilter("udp and ( port 67 or port 68 )", BpfCompileMode.OPTIMIZE)


    val executorService: ExecutorService = Executors.newCachedThreadPool()
    val ex = ExecutionContext.fromExecutor(executorService)

    Future {
      try {
        handle.loop(-1, new PacketListener {
          override def gotPacket(packet: Packet): Unit = handlePacket(dhcpService, handle, selfMac)(packet)
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


  def handlePacket(dhcpService: DhcpService, pcapHandle: PcapHandle, macAddress: MacAddress)(packet: Packet): Unit = packet match {
    case eth: EthernetPacket =>
      //      println(s"Ethernet ${eth.getHeader.getSrcAddr} -> ${eth.getHeader.getDstAddr}")
      eth.getPayload match {
        case v4: IpV4Packet =>
          //          println(s"  IPv4 ${v4.getHeader.getSrcAddr} -> ${v4.getHeader.getDstAddr}")
          v4.getPayload match {
            case udp: UdpPacket =>
              //              println(s"    UDP ${udp.getHeader.getSrcPort} -> ${udp.getHeader.getDstPort}")
              if (udp.getHeader.getDstPort.valueAsInt() == 67) {
                println("=============================")
                println(s"DHCP ${eth.getHeader.getSrcAddr} ${udp.getHeader.getSrcPort} -> ${udp.getHeader.getDstPort}")

                BootpPacket.parseOpt(udp.getPayload.getRawData) match {
                  case Some(parsed) =>
                    dhcpService.recive(parsed) onComplete {
                      case Success(Some(value)) =>
                        println(">>>>>")
                        val resBytes = value.asBytes
                        val padding = resBytes ++ Bytes.fill(udp.getPayload.length() - resBytes.length)(0)
                        import fastparse.byte.ByteUtils.prettyBytes
                        println(prettyBytes(padding, contextRows = 30))
                        val resArr = padding.toArray
                        val bootpPayload: UnknownPacket = UnknownPacket.newPacket(resArr, 0, resArr.length)

                        val src = InetAddress.getByName("10.0.0.1").asInstanceOf[Inet4Address]
                        val dst = value.yourClientIp
                        val newUdp = new UdpPacket.Builder()
                          .payloadBuilder(bootpPayload.getBuilder)
                          .correctChecksumAtBuild(true)
                          .correctLengthAtBuild(true)
                          .srcPort(UdpPort.BOOTPS)
                          .dstPort(UdpPort.BOOTPC)
                          .srcAddr(src)
                          .dstAddr(dst)
                        val newIp = new IpV4Packet.Builder(v4)
                          .srcAddr(src)
                          .dstAddr(dst)
                          .version(IpVersion.IPV4)
                          .protocol(IpNumber.UDP)
                          .ttl(64)
                          .payloadBuilder(newUdp)
                          .correctChecksumAtBuild(true)
                          .correctLengthAtBuild(true)
                        val newEth = new EthernetPacket.Builder()
                          .srcAddr(macAddress)
                          .dstAddr(eth.getHeader.getSrcAddr)
                          .`type`(EtherType.IPV4)
                          .payloadBuilder(newIp)
                          .paddingAtBuild(true)

                        pcapHandle.sendPacket(newEth.build())
                      case Success(None) =>
                      case Failure(exception) =>
                        exception.printStackTrace()
                    }
                  case None =>
                    println("failed parse")
                }
              }
          }
      }
    case _ => // not ethernet packet
  }
}
