import java.net.InetSocketAddress

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import akka.io.{IO, Udp}
import akka.util.ByteString
import fastparse.core.Parsed
import model.BootpPacket

import scala.io.StdIn
import scala.util.{Failure, Success}

object AkkaUdpSandbox {
  def main(args: Array[String]): Unit = {
    val system = ActorSystem()
    val routerRef = system.actorOf(Props(new Router))
    val listenerRef = system.actorOf(Props(new Listener(routerRef)))
    sys.addShutdownHook({
      println("shutdown...")
      system.terminate()
    })

    StdIn.readLine()
    system.terminate()
  }
}

case class MyPacket(address: InetSocketAddress, data: ByteString, socket: ActorRef)

class Router extends Actor {
  implicit val ctx = context.dispatcher
  val dhcpService = new DhcpService

  override def receive: Receive = {
    case packet: MyPacket =>
      println(s"from: ${packet.address}")

      BootpPacket.parse(packet.data.asByteBuffer) match {
        case Parsed.Success(x, index) =>
          dhcpService.recive(x).onComplete {
            case Success(Some(returnPacket)) =>
              val bs = ByteString(returnPacket.asBytes.toArray)
              val socketAddress = new InetSocketAddress(returnPacket.yourClientIp, 68)
              packet.socket ! Udp.Send(bs, socketAddress)
              println(s"<===send $socketAddress ${returnPacket}")
            case Success(None) =>
              println("none output")
            case Failure(exception) =>
              exception.printStackTrace()
          }
        case failure: Parsed.Failure[_, _] =>
          println(s"parse error ${failure.msg}")
      }
  }
}

class Listener(nextActor: ActorRef) extends Actor {

  import context.system

  IO(Udp) ! Udp.Bind(
    self,
    new InetSocketAddress("0.0.0.0", 67),
    List(Udp.SO.Broadcast(true))
  )

  override def receive: Receive = {
    case Udp.Bound(local) ⇒
      nextActor forward local
      context.become(ready(sender()))
  }

  def ready(socket: ActorRef): Receive = {
    case Udp.Received(data, remote) ⇒
      val processed = data.utf8String
//       socket ! Udp.Send(data, remote) // example server echoes back
      nextActor ! MyPacket(remote, data, socket)
    case Udp.Unbind ⇒ socket ! Udp.Unbind
    case Udp.Unbound ⇒ context.stop(self)
  }
}
