# QuicDraw is a client for fuzzing and racing HTTP/3 servers.
# It can send GET and POST requests.
# It is designed to be used with and based on the aioquic(https://github.com/aiortc/aioquic) library.
# GitHub: https://github.com/cyberark/quicdraw
# License: Apache-2.0 License
# Author: Maor Abutbul <CyberArk Labs>

# Version and description
__version__ = "0.8.29"
__description__ = "QuicDraw(H3): HTTP/3 Fuzzing and Racing (Client)"

import argparse
import asyncio
import logging
import os
import ssl
import time
from collections import deque
from typing import BinaryIO, Callable, Deque, Dict, List, Optional, Union, cast
from urllib.parse import urlparse

import aioquic
import wsproto.events
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.tls import CipherSuite, SessionTicket
from wsproto.connection import Connection

try:
    import uvloop  # type: ignore
except ImportError:
    uvloop = None

logger = logging.getLogger("QuicDraw")
HttpConnection = Union[H0Connection, H3Connection]
USER_AGENT = "aioquic/" + aioquic.__version__
start_time = time.time()


class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)

        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme


class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}

        self.content = content
        self.headers = headers
        self.method = method
        self.url = url


class WebSocket:
    def __init__(
        self, http: HttpConnection, stream_id: int, transmit: Callable[[], None]
    ) -> None:
        self.http = http
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.stream_id = stream_id
        self.subprotocol: Optional[str] = None
        self.transmit = transmit
        self.websocket = Connection(wsproto.connection.ConnectionType.CLIENT)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        """
        Perform the closing handshake.
        """
        data = self.websocket.send(
            wsproto.events.CloseConnection(code=code, reason=reason)
        )
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=True)
        self.transmit()

    async def recv(self) -> str:
        """
        Receive the next message.
        """
        return await self.queue.get()

    async def send(self, message: str) -> None:
        """
        Send a message.
        """
        assert isinstance(message, str)

        data = self.websocket.send(wsproto.events.TextMessage(data=message))
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=False)
        self.transmit()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            for header, value in event.headers:
                if header == b"sec-websocket-protocol":
                    self.subprotocol = value.decode()
        elif isinstance(event, DataReceived):
            self.websocket.receive_data(event.data)

        for ws_event in self.websocket.events():
            self.websocket_event_received(ws_event)

    def websocket_event_received(self, event: wsproto.events.Event) -> None:
        if isinstance(event, wsproto.events.TextMessage):
            self.queue.put_nowait(event.data)


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: Optional[HttpConnection] = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._websockets: Dict[int, WebSocket] = {}

        alpn_protocols = getattr(self._quic.configuration, "alpn_protocols", None)
        if (
            alpn_protocols
            and len(alpn_protocols) > 0
            and alpn_protocols[0].startswith("hq-")
        ):
            self._http = H0Connection(self._quic)
        else:
            self._http = H3Connection(self._quic)

    async def send_get_streams(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        wordlist: Optional[str] = None,
        total_requests: Optional[int] = 1,
    ) -> List[Deque[H3Event]]:
        """
        Perform a GET request.
        """
        return await self._send_get_requests(
            HttpRequest(method="GET", url=URL(url), headers=headers),
            the_wordlist=wordlist,
            total_requests=total_requests,
        )

    async def send_post_streams(
        self,
        url: str,
        data: str,
        headers: Optional[Dict[str, str]] = None,
        wordlist: Optional[str] = None,
        total_requests: Optional[int] = 1,
    ) -> List[Deque[H3Event]]:
        """
        Perform a POST request.
        """
        data_bytes = data.encode() if isinstance(data, str) else data
        return await self._send_post_requests(
            HttpRequest(
                method="POST", url=URL(url), content=data_bytes, headers=headers
            ),
            the_wordlist=wordlist,
            total_requests=total_requests,
        )

    async def websocket(
        self, url: str, subprotocols: Optional[List[str]] = None
    ) -> WebSocket:
        """
        Open a WebSocket.
        """
        request = HttpRequest(method="CONNECT", url=URL(url))
        stream_id = self._quic.get_next_available_stream_id()
        if self._http is None:
            raise RuntimeError("HTTP connection is not initialized.")
        websocket = WebSocket(
            http=self._http, stream_id=stream_id, transmit=self.transmit
        )

        self._websockets[stream_id] = websocket

        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
            (b":protocol", b"websocket"),
            (b"user-agent", USER_AGENT.encode()),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append(
                (b"sec-websocket-protocol", ", ".join(subprotocols).encode())
            )
        if self._http is not None:
            self._http.send_headers(stream_id=stream_id, headers=headers)

        self.transmit()

        return websocket

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            logger.debug(
                "HTTP Response Received (stream:{0}) Arrived: {1}".format(
                    stream_id, time.time() - start_time
                )
            )
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

            elif stream_id in self._websockets:
                # websocket
                websocket = self._websockets[stream_id]
                websocket.http_event_received(event)

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _send_get_requests(
        self, request: HttpRequest, the_wordlist, total_requests
    ) -> List[Deque[H3Event]]:
        waiters_bulk_list = []
        total_streams = 5
        base_stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_ping(7777)
        modified_full_paths = []
        if the_wordlist and os.path.isfile(the_wordlist):
            logger.info("Using wordlist file %s", the_wordlist)
            with open(the_wordlist, "r", encoding="utf-8") as f:
                wordlist = f.read().splitlines()
                total_streams = len(wordlist)
                if total_requests != total_streams:
                    logger.warning(
                        "Total requests is set to %d, but wordlist contains %d words. using count from wordlist file %d",
                        total_requests,
                        total_streams,
                        total_streams,
                    )
                logger.info("Total streams to be sent: %d", total_streams)
                for i in range(0, total_streams):
                    stream_id = base_stream_id + i * 4
                    full_path = request.url.full_path
                    if i < len(wordlist):
                        # Use the word from the wordlist
                        full_path = full_path.replace("FUZZ", wordlist[i])
                    else:
                        # If we run out of words, just use the last one
                        full_path = full_path.replace("FUZZ", wordlist[-1])
                    modified_full_paths.append(full_path)
        else:
            if the_wordlist:
                logger.warning("Wordlist file %s does not exist", the_wordlist)
                raise FileNotFoundError(f"Wordlist file {the_wordlist} does not exist.")
            else:
                logger.debug("No wordlist file provided, using data as is")
            total_streams = (
                total_requests  # use total_requests as the number of streams
            )
            for i in range(0, total_streams):
                # Using the :path as is (no modifications)
                modified_full_paths.append(request.url.full_path)

        for i in range(0, len(modified_full_paths)):
            stream_id = base_stream_id + i * 4
            if self._http is not None:
                self._http.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b":method", request.method.encode()),
                        (b":scheme", request.url.scheme.encode()),
                        (b":authority", request.url.authority.encode()),
                        (b":path", str(modified_full_paths[i]).encode()),
                        (b"user-agent", USER_AGENT.encode()),
                    ]
                    + [(k.encode(), v.encode()) for (k, v) in request.headers.items()],
                    end_stream=True,
                )
            else:
                logger.error("HTTP connection (Error) - not initialized.")
                continue
            logger.debug(
                "Request (stream:{0}) GET :authority {1} :path  {2}".format(
                    stream_id, request.url.authority, modified_full_paths[i]
                )
            )
            waiter = self._loop.create_future()
            self._request_events[stream_id] = deque()
            self._request_waiter[stream_id] = waiter
            waiters_bulk_list.append(waiter)
        self.transmit()
        return await asyncio.gather(*waiters_bulk_list)

    async def _send_post_requests(
        self, request: HttpRequest, the_wordlist, total_requests
    ) -> List[Deque[H3Event]]:
        waiters_list = []
        waiters_bulk_list = []
        total_streams = 1
        base_stream_id = self._quic.get_next_available_stream_id()
        modified_requests_data = []
        self._quic.send_ping(7777)
        if the_wordlist and os.path.isfile(the_wordlist):
            logger.info("Using wordlist file %s", the_wordlist)
            with open(the_wordlist, "r", encoding="utf-8") as f:
                wordlist = f.read().splitlines()
                total_streams = len(wordlist)
                if total_requests != total_streams:
                    logger.warning(
                        "Total requests is set to %d, but wordlist contains %d words. using count from wordlist file %d",
                        total_requests,
                        total_streams,
                        total_streams,
                    )
                logger.info("Total streams to be sent: %d", total_streams)
                for i in range(0, total_streams):
                    stream_id = base_stream_id + i * 4
                    data = request.content
                    if i < len(wordlist):
                        # Use the word from the wordlist
                        data = data.replace(b"FUZZ", wordlist[i].encode())
                    else:
                        # If we run out of words, just use the last one
                        data = data.replace(b"FUZZ", wordlist[i].encode())
                    modified_requests_data.append(data)
        else:
            if the_wordlist:
                logger.warning("Wordlist file %s does not exist", the_wordlist)
                raise FileNotFoundError(f"Wordlist file {the_wordlist} does not exist.")
            else:
                logger.debug("No wordlist file provided, using data as is")
            total_streams = (
                total_requests  # use total_requests as the number of streams
            )
            data = request.content  # using the content (data) as is (no modifications)
            logger.info("Using data as is for %d streams", total_streams)
            for i in range(0, total_streams):
                stream_id = base_stream_id + i * 4
                modified_requests_data.append(data)
        # Buffer the requests
        for i in range(0, len(modified_requests_data)):
            stream_id = base_stream_id + i * 4
            if self._http is not None:
                self._http.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b":method", request.method.encode()),
                        (b":scheme", request.url.scheme.encode()),
                        (b":authority", request.url.authority.encode()),
                        (b":path", request.url.full_path.encode()),
                        (b"user-agent", USER_AGENT.encode()),
                        (
                            b"content-length",
                            str(len(modified_requests_data[i])).encode(),
                        ),
                    ]
                    + [(k.encode(), v.encode()) for (k, v) in request.headers.items()],
                    end_stream=False,
                )
                self._http.send_data(
                    stream_id=stream_id,
                    data=modified_requests_data[i][:-1],
                    end_stream=False,
                )
            else:
                logger.error("HTTP connection (Error) - not initialized.")
                continue
            logger.debug(
                "Request (stream:{0}) POST Data {1}".format(
                    stream_id, modified_requests_data[i]
                )
            )
            waiter = self._loop.create_future()
            self._request_events[stream_id] = deque()
            self._request_waiter[stream_id] = waiter
            waiters_bulk_list.append(waiter)
        # send the headers and the data in chunks
        self.transmit()
        asyncio.gather(*waiters_bulk_list)
        # wait for the headers and (most of the) data to be sent.
        await asyncio.sleep(1.0)
        self._quic.send_ping(9999)  # send a ping to ensure the connection is alive.
        # send the last byte of data to end the stream
        for i in range(0, len(modified_requests_data)):
            stream_id = base_stream_id + i * 4
            if request.content:
                if self._http is not None:
                    self._http.send_data(
                        stream_id=stream_id,
                        data=modified_requests_data[i][-1:],
                        end_stream=True,
                    )
                    waiter = self._loop.create_future()
                    self._request_events[stream_id] = deque()
                    self._request_waiter[stream_id] = waiter
                    waiters_list.append(waiter)
                else:
                    logger.error("HTTP connection (Error).")
                    continue
        self.transmit()
        return await asyncio.gather(*waiters_list)


async def perform_http_requests(
    client: HttpClient,
    url: str,
    data: Optional[str],
    extra_headers: Optional[list[str]],
    wordlist: Optional[str],
    total_requests: Optional[int],
    include: bool,
    output_dir: Optional[str],
) -> None:
    # perform request
    headers = []
    if extra_headers is not None:
        for extra_header in extra_headers:
            the_header = extra_header[0].split(":", 1)
            if len(the_header) == 2:
                headers.append((the_header[0].strip().lower(), the_header[1].strip()))
    headers_dict = dict(headers)

    if data is not None:
        http_events_queues = await client.send_post_streams(
            url,
            data=data,
            headers=headers_dict,
            wordlist=wordlist,
            total_requests=total_requests,
        )
        method = "POST"
    else:
        http_events_queues = await client.send_get_streams(
            url=url,
            headers=headers_dict,
            wordlist=wordlist,
            total_requests=total_requests,
        )
        method = "GET"

    # print content
    for http_events in http_events_queues:
        octets = 0
        the_data = b""
        last_stream_id = None
        for http_event in http_events:
            if isinstance(http_event, DataReceived):
                the_data += http_event.data
                octets += len(http_event.data)
                last_stream_id = http_event.stream_id
            elif isinstance(http_event, HeadersReceived):
                last_stream_id = http_event.stream_id
                for header, value in http_event.headers:
                    if header == b":status":
                        status = value.decode()
                        logger.info(
                            "Response headers received (stream:{0}) {1} {2} : status: ({3})".format(
                                http_event.stream_id, method, urlparse(url).path, status
                            )
                        )
                    if include:
                        print(
                            "Response header received (stream:{0}) {1} {2}".format(
                                http_event.stream_id, header, value.decode()
                            )
                        )
                    logger.debug(
                        "Response header received (stream:{0}) {1} {2}".format(
                            http_event.stream_id, header, value.decode()
                        )
                    )
        logger.info(
            "Response data   received (stream:{0}) {1} {2} : {3} bytes".format(
                last_stream_id if last_stream_id is not None else "-",
                method,
                urlparse(url).path,
                octets,
            )
        )
        logger.debug(
            "Response data content (stream:{1}): |{0}|\n".format(
                the_data, last_stream_id if last_stream_id is not None else "-"
            )
        )

        # output response
        if output_dir is not None:
            output_path = os.path.join(
                output_dir,
                os.path.basename(
                    urlparse(url).path + "_Stream_{0}".format(last_stream_id)
                )
                or "index.html",
            )
            with open(output_path, "wb") as output_file:
                write_response(
                    http_events=http_events, include=include, output_file=output_file
                )


def process_http_pushes(
    client: HttpClient,
    include: bool,
    output_dir: Optional[str],
) -> None:
    for _, http_events in client.pushes.items():
        method = ""
        octets = 0
        path = ""
        for http_event in http_events:
            if isinstance(http_event, DataReceived):
                octets += len(http_event.data)
            elif isinstance(http_event, PushPromiseReceived):
                for header, value in http_event.headers:
                    if header == b":method":
                        method = value.decode()
                    elif header == b":path":
                        path = value.decode()
        logger.info("Push received for %s %s : %s bytes", method, path, octets)

        # output response
        if output_dir is not None:
            output_path = os.path.join(
                output_dir, os.path.basename(path) or "index.html"
            )
            with open(output_path, "wb") as output_file:
                write_response(
                    http_events=http_events, include=include, output_file=output_file
                )


def write_response(
    http_events: Deque[H3Event], output_file: BinaryIO, include: bool
) -> None:
    for http_event in http_events:
        if isinstance(http_event, HeadersReceived) and include:
            headers = b""
            for k, v in http_event.headers:
                headers += k + b": " + v + b"\r\n"
            if headers:
                output_file.write(headers + b"\r\n")
        elif isinstance(http_event, DataReceived):
            output_file.write(http_event.data)


def save_session_ticket(ticket: SessionTicket) -> None:
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.debug("New session ticket received - Not saving to file.")
    # if args.session_ticket:
    #    with open(args.session_ticket, "wb") as fp:
    #        pickle.dump(ticket, fp)


async def main(
    configuration: QuicConfiguration,
    urls: List[str],
    data: Optional[str],
    extra_headers: Optional[list[str]],
    wordlist: Optional[str],
    total_requests: int,
    include: bool,
    output_dir: Optional[str],
    local_port: int,
    zero_rtt: bool,
) -> None:
    # parse URL
    parsed = urlparse(urls[0])
    assert parsed.scheme in (
        "https",
        "wss",
    ), "Only https:// or wss:// URLs are supported."
    host = parsed.hostname
    if host is None:
        raise ValueError("URL must include a hostname.")
    if parsed.port is not None:
        port = parsed.port
    else:
        port = 443

    # check validity of 2nd urls and later.
    for i in range(1, len(urls)):
        _p = urlparse(urls[i])

        # fill in if empty
        _scheme = _p.scheme or parsed.scheme
        _host = _p.hostname or host
        _port = _p.port or port

        assert _scheme == parsed.scheme, "URL scheme doesn't match"
        assert _host == host, "URL hostname doesn't match"
        assert _port == port, "URL port doesn't match"

        # reconstruct url with new hostname and port
        _p = _p._replace(scheme=_scheme)
        _p = _p._replace(netloc="{}:{}".format(_host, _port))
        _p = urlparse(_p.geturl())
        urls[i] = _p.geturl()

    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
        session_ticket_handler=save_session_ticket,
        local_port=local_port,
        wait_connected=not zero_rtt,
    ) as client:
        client = cast(HttpClient, client)

        if parsed.scheme == "wss":
            ws = await client.websocket(urls[0], subprotocols=["chat", "superchat"])

            # send some messages and receive reply
            for i in range(2):
                message = "Hello {}, WebSocket!".format(i)
                print("> " + message)
                await ws.send(message)

                message = await ws.recv()
                print("< " + message)

            await ws.close()
        else:
            # perform request
            coros = [
                perform_http_requests(
                    client=client,
                    url=url,
                    data=data,
                    extra_headers=extra_headers,
                    wordlist=wordlist,
                    total_requests=total_requests,
                    include=include,
                    output_dir=output_dir,
                )
                for url in urls
            ]
            await asyncio.gather(*coros)

            # process http pushes
            process_http_pushes(client=client, include=include, output_dir=output_dir)
        client.close(error_code=ErrorCode.H3_NO_ERROR)


logo = rf"""
    -----------
    {__description__}
    -----------
               _         _
              (_)       | |                          ______
    __ _ _   _ _  ___ __| |_ __ __ ___      __  /\  /\___ /
   / _` | | | | |/ __/ _` | '__/ _` \ \ /\ / / / /_/ / |_ \
  | (_| | |_| | | (_| (_| | | | (_| |\ V  V / / __  / ___) |
   \__, |\__,_|_|\___\__,_|_|  \__,_| \_/\_/  \/ /_/ |____/
      |_|    _______
         \  |QFS____| -------------------- HTTP/3
          \ |_//
            |_|

    GitHub: https://github.com/cyberark/QuicDrawH3
    License: Apache-2.0 License
    Author: Maor Abutbul <CyberArk Labs>
    Version: {__version__}
    -----------
"""


def print_logo():
    print(logo)


class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        # Add the logo at the top of the help message
        print_logo()
        return super().add_usage(
            prefix=("Usage: \n"), usage=usage, actions=actions, groups=groups
        )


def cli_main():
    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(
        formatter_class=CustomHelpFormatter, epilog="Version: " + __version__
    )
    parser.add_argument(
        "url",
        type=str,
        help="the URL to query (must be HTTPS)",
        nargs="+",  # we do not support multiple URLs in this version
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument(
        "--certificate",
        type=str,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "--cipher-suites",
        type=str,
        help=(
            "only advertise the given cipher suites, e.g. `AES_256_GCM_SHA384,"
            "CHACHA20_POLY1305_SHA256`"
        ),
    )
    parser.add_argument(
        "--congestion-control-algorithm",
        type=str,
        default="reno",
        help="use the specified congestion control algorithm",
    )
    parser.add_argument(
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        type=str,
        help="send the specified data in a POST request",
    )
    parser.add_argument(
        "-H",
        "--header",
        type=str,
        action="append",
        nargs="+",
        help="add the following header to each request, can be used more then once. e.g. -H 'X-Header: header_value'",
    )
    parser.add_argument(
        "-b",
        "--cookie",
        type=str,
        action="append",
        help="add the following cookie to each request -b 'cookie_value'",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        type=str,
        help="use the specified wordlist to generate data for POST requests,"
        "e.g. -w wordlist.txt. The wordlist should contain one word per line.",
    )
    parser.add_argument(
        "-tr",
        "--total-requests",
        type=int,
        help="Number of requests to send, the a provided wordlist overrides this argument, will use the number of words (lines) in the wordlist file (default: 1)",
        default=1,
    )
    parser.add_argument(
        "-i",
        "--include",
        action="store_true",
        help="include the HTTP response headers in the output",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "--legacy-http",
        action="store_true",
        help="use HTTP/0.9",
    )
    parser.add_argument(
        "--max-data",
        type=int,
        help="connection-wide flow control limit (default: %d)" % defaults.max_data,
    )
    parser.add_argument(
        "--max-stream-data",
        type=int,
        help="per-stream flow control limit (default: %d)" % defaults.max_stream_data,
    )
    parser.add_argument(
        "--negotiate-v2",
        action="store_true",
        help="start with QUIC v1 and try to negotiate QUIC v2",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        help="write downloaded files to this directory",
    )
    parser.add_argument(
        "--private-key",
        type=str,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        help="increase logging verbosity -vv=debug",
        default=0,
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=0,
        help="local port to bind for connections",
    )
    parser.add_argument(
        "--max-datagram-size",
        type=int,
        default=defaults.max_datagram_size,
        help="maximum datagram size to send, excluding UDP or IP overhead",
    )
    parser.add_argument(
        "--zero-rtt", action="store_true", help="try to send requests using 0-RTT"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose >= 1 else logging.INFO,
    )
    logging.getLogger("quic").setLevel(
        logging.DEBUG if args.verbose >= 2 else logging.WARNING
    )

    logger.debug("Version: {0}".format(__version__))

    if args.output_dir is not None and not os.path.isdir(args.output_dir):
        raise Exception("%s is not a directory" % args.output_dir)

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H0_ALPN if args.legacy_http else H3_ALPN,
        congestion_control_algorithm=args.congestion_control_algorithm,
        max_datagram_size=args.max_datagram_size,
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.cipher_suites:
        configuration.cipher_suites = [
            CipherSuite[s] for s in args.cipher_suites.split(",")
        ]
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.max_data:
        configuration.max_data = args.max_data
    if args.max_stream_data:
        configuration.max_stream_data = args.max_stream_data
    if args.negotiate_v2:
        configuration.original_version = QuicProtocolVersion.VERSION_1
        configuration.supported_versions = [
            QuicProtocolVersion.VERSION_2,
            QuicProtocolVersion.VERSION_1,
        ]
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    # if args.session_ticket:
    #     try:
    #         with open(args.session_ticket, "rb") as fp:
    #             configuration.session_ticket = pickle.load(fp)
    #     except FileNotFoundError:
    #         pass

    # load SSL certificate and key
    if args.certificate is not None:
        configuration.load_cert_chain(args.certificate, args.private_key)

    extra_headers_and_cookie = args.header if args.header else []
    if args.cookie is not None:
        extra_headers_and_cookie.append(["cookie: {}".format(args.cookie[0])])

    if uvloop is not None:
        uvloop.install()
    asyncio.run(
        main(
            configuration=configuration,
            urls=args.url,
            data=args.data,
            extra_headers=extra_headers_and_cookie,
            wordlist=args.wordlist,
            total_requests=args.total_requests,
            include=args.include,
            output_dir=args.output_dir,
            local_port=args.local_port,
            zero_rtt=args.zero_rtt,
        )
    )


if __name__ == "__main__":
    try:
        cli_main()
    except KeyboardInterrupt:
        print("\nQuicDraw interrupted by user.")
    except Exception as e:
        logger.error(
            "An error occurred: %s : %s",
            e.__class__.__name__ if e.__class__ is not None else "",
            str(e),
        )
        exit(1)
