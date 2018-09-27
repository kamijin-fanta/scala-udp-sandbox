import java.net.InetSocketAddress

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import akka.io.{IO, Udp}
import akka.util.ByteString

import scala.io.StdIn

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

case class MyPacket(address: InetSocketAddress, data: ByteString)

class Router extends Actor {
  override def receive: Receive = {
    case packet: MyPacket => println(s"from: ${packet.address} data: ${packet.data.utf8String}")
  }
}

class Listener(nextActor: ActorRef) extends Actor {
  import context.system
  IO(Udp) ! Udp.Bind(
    self,
    new InetSocketAddress("0.0.0.0",67),
    List(Udp.SO.Broadcast(true))
  )

  override def receive: Receive = {
    case Udp.Bound(local) ⇒
      //#listener
      nextActor forward local
      //#listener
      context.become(ready(sender()))
  }

  def ready(socket: ActorRef): Receive = {
    case Udp.Received(data, remote) ⇒
      val processed = // parse data etc., e.g. using PipelineStage
      //#listener
        data.utf8String
      //#listener
      // socket ! Udp.Send(data, remote) // example server echoes back
      nextActor ! MyPacket(remote, data)
    case Udp.Unbind  ⇒ socket ! Udp.Unbind
    case Udp.Unbound ⇒ context.stop(self)
  }
}
