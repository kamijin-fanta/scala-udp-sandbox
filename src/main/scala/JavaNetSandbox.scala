
import java.net.{DatagramPacket, DatagramSocket, InetAddress}

import scala.io.StdIn

object JavaNetSandbox {
  def main(args: Array[String]): Unit = {
    val server = new EchoServer
    server.run()

    StdIn.readLine()
    server.socket.close()
  }
}


class EchoServer() {
  val addr: InetAddress = InetAddress.getByName("172.25.15.255")
  val socket = new DatagramSocket(17500, addr)
  socket.setBroadcast(true)
  private var running = false
  private val buf = new Array[Byte](256)

  def run(): Unit = {
    running = true
    while ( {
      running
    }) {
      var packet = new DatagramPacket(buf, buf.length)
      socket.receive(packet)
      val address = packet.getAddress
      val port = packet.getPort
      println(s"rcv: $address $port")
      packet = new DatagramPacket(buf, buf.length, address, port)
      val received = new String(packet.getData, 0, packet.getLength)
      if (received == "end") {
        running = false
      }
      socket.send(packet)
    }
    socket.close()
  }
}