"""Bounded TCP delivered-goodput probe; Python 3.8+, no dependencies."""
import argparse
import concurrent.futures
import json
import re
import socket
import socketserver
import subprocess
import time

BLOCK = b'\0' * 65536

def header(sock):
    data = bytearray()
    while not data.endswith(b'\n'):
        item = sock.recv(1)
        if not item or len(data) > 4096:
            raise ValueError('Invalid probe header')
        data.extend(item)
    return json.loads(data)

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(15)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1200)
        try:
            cfg = header(sock)
            duration = min(12, max(3, float(cfg['duration'])))
            warmup = 2
            sock.sendall(b'READY\n')
            start = time.monotonic()
            count = 0
            if cfg['direction'] == 'ul':
                while time.monotonic() - start < duration + 10:
                    item = sock.recv(65536)
                    if not item:
                        break
                    elapsed = time.monotonic() - start
                    if warmup <= elapsed <= duration:
                        count += len(item)
                sock.sendall(json.dumps(dict(bytes=count,seconds=duration-warmup)).encode()+b'\n')
                sock.shutdown(socket.SHUT_WR)
            else:
                sock.settimeout(0.2)
                while time.monotonic() - start < duration:
                    try:
                        sock.send(BLOCK)
                    except socket.timeout:
                        continue
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(5)
                sock.recv(1)
        except (OSError, ValueError, KeyError) as exc:
            print(json.dumps(dict(peer=self.client_address,error=repr(exc))),flush=True)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

def stream(args):
    start_cpu = time.process_time()
    with socket.socket() as sock:
        sock.settimeout(15)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1200)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
        sock.bind((args.source, 0))
        sock.connect((args.target, args.port))
        sock.sendall(json.dumps(dict(duration=args.duration,direction=args.direction)).encode()+b'\n')
        ready = bytearray()
        while not ready.endswith(b'\n'):
            item = sock.recv(1)
            if not item:
                raise RuntimeError('Receiver closed before READY')
            ready.extend(item)
        start = time.monotonic()
        count = 0
        error = None
        if args.direction == 'ul':
            sock.settimeout(0.2)
            while time.monotonic() - start < args.duration:
                try:
                    sock.send(BLOCK)
                except socket.timeout:
                    continue
                except BrokenPipeError:
                    break
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(15)
            report = header(sock)
            count, seconds = report['bytes'], report['seconds']
        else:
            while True:
                try:
                    item = sock.recv(65536)
                except (ConnectionResetError, socket.timeout) as exc:
                    error = repr(exc)
                    break
                if not item:
                    break
                elapsed = time.monotonic() - start
                if 2 <= elapsed <= args.duration:
                    count += len(item)
            seconds = args.duration - 2
        return dict(bytes=count,seconds=seconds,mbps=count*8/seconds/1e6,cpu_seconds=time.process_time()-start_cpu,error=error,observed_seconds=time.monotonic()-start)

def path_quality(source,target,count,interval):
    """RTT/jitter/loss via ping; additive, independent of the TCP goodput probe above."""
    cmd=['ping','-n','-c',str(count),'-i',str(interval),'-W','2']
    if source:cmd[1:1]=['-I',source]
    cmd.append(target)
    proc=subprocess.run(cmd,capture_output=True,text=True,timeout=count*interval+15)
    loss=re.search(r'(\d+(?:\.\d+)?)% packet loss',proc.stdout)
    if loss is None:
        raise RuntimeError('Could not parse ping loss: '+(proc.stderr or proc.stdout)[-500:])
    rtt=re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',proc.stdout)
    return dict(loss_pct=float(loss.group(1)),
                rtt_ms=dict(min=float(rtt.group(1)),avg=float(rtt.group(2)),max=float(rtt.group(3)),mdev=float(rtt.group(4))) if rtt else None,
                count=count,interval_s=interval,raw_returncode=proc.returncode)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=['server','client','path'])
    parser.add_argument('--target',default='10.55.0.100')
    parser.add_argument('--port',type=int,default=19090)
    parser.add_argument('--source')
    parser.add_argument('--direction',choices=['ul','dl'],default='ul')
    parser.add_argument('--duration',type=float,default=10)
    parser.add_argument('--streams',type=int,default=2)
    parser.add_argument('--count',type=int,default=30,help='path mode: ICMP probes')
    parser.add_argument('--interval',type=float,default=.2,help='path mode: seconds between ICMP probes')
    args=parser.parse_args()
    if args.mode=='server':
        with Server((args.target,args.port),Handler) as server:
            server.serve_forever()
    elif args.mode=='path':
        print(json.dumps(dict(source=args.source,target=args.target,**path_quality(args.source,args.target,args.count,args.interval))),flush=True)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.streams) as pool:
            results=list(pool.map(lambda _:stream(args),range(args.streams)))
        print(json.dumps(dict(source=args.source,direction=args.direction,streams=results,mbps=sum(r['mbps'] for r in results))),flush=True)

if __name__=='__main__':
    main()
