// Copyright (c) The btclib developers
// Distributed under the MIT software license, see the accompanying
// LICENSE file or https://opensource.org/license/mit for the full text.

//> using scala 2.13.18
//> using dep org.bitcoin-s:bitcoin-s-core_2.13:1.9.12

import org.bitcoins.core.psbt.PSBT
import scala.util.control.NonFatal

/** One result per input line, so a refused PSBT cannot hide its neighbours. */
object PsbtRoundTrip extends App {
  def quoted(value: String): String = {
    val escaped = value.flatMap {
      case '"' => "\\\""
      case '\\' => "\\\\"
      case c if c < ' ' => f"\\u${c.toInt}%04x"
      case c => c.toString
    }
    "\"" + escaped + "\""
  }

  scala.io.Source.stdin.getLines().zipWithIndex.foreach { case (line, index) =>
    try {
      val encoded = PSBT.fromBase64(line).base64
      println(s"{\"index\":$index,\"ok\":true,\"base64\":${quoted(encoded)}}")
    } catch {
      case NonFatal(error) =>
        val kind = quoted(error.getClass.getName)
        val message = quoted(Option(error.getMessage).getOrElse(""))
        println(
          s"{\"index\":$index,\"ok\":false,\"error_type\":$kind,\"error\":$message}"
        )
    }
  }
}
