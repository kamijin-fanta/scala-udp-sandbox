name := "scala-udp-sandbox"

version := "0.1"

scalaVersion := "2.12.6"


libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" % "2.5.16",
  "com.lihaoyi" %% "fastparse" % "1.0.0",
  "com.lihaoyi" %% "fastparse-byte" % "1.0.0",
  "org.pcap4j" % "pcap4j-core" % "1.7.3",
  "org.pcap4j" % "pcap4j-packetfactory-static" % "1.7.3",
  "org.scalatest" %% "scalatest" % "3.0.5" % Test
)
