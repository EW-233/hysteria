"""分析只含包头的 Linux cooked v2 抓包，核对回环 Initial 与外网短头数据。"""
import argparse
import collections
import json
import socket
import struct
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument("pcap",type=Path)
p.add_argument("--server",default="192.0.2.20")
p.add_argument("--data-port",type=int,default=8443)
a=p.parse_args()
raw=a.pcap.read_bytes()
assert raw[:4] in (bytes.fromhex("d4c3b2a1"),bytes.fromhex("a1b2c3d4")), "unsupported PCAP format"
e="<" if raw[:4]==bytes.fromhex("d4c3b2a1") else ">"
assert struct.unpack_from(e+"I",raw,20)[0]==276,"requires LINUX_SLL2"
offset=24
stats=collections.Counter(); flows=collections.defaultdict(collections.Counter)
while offset+16<=len(raw):
    _,_,size,_=struct.unpack_from(e+"4I",raw,offset);offset+=16
    frame=raw[offset:offset+size];offset+=size
    if len(frame)<48 or frame[:2]!=bytes.fromhex("0800"):continue
    ip=frame[20:]
    if ip[0]>>4!=4 or ip[9]!=17:continue
    ihl=(ip[0]&15)*4
    if len(ip)<ihl+9:continue
    src,dst=socket.inet_ntoa(ip[12:16]),socket.inet_ntoa(ip[16:20])
    sport,dport,_,_=struct.unpack_from("!4H",ip,ihl)
    payload=ip[ihl+8:]
    initial=len(payload)>6 and payload[0]&128 and (payload[0]>>4)&3==0 and payload[1:5]==bytes.fromhex("00000001")
    short=not payload[0]&128
    if src.startswith("127.") and dst.startswith("127."):
        stats["loopbackPackets"]+=1
        if initial:
            stats["loopbackInitials"]+=1
    if dst==a.server and dport==a.data_port:
        label=f"source-port-{sport}"
        flows[label]["packets"]+=1
        if initial: flows[label]["initials"]+=1
        if short:
            flows[label]["shortHeaders"]+=1
        stats["externalInboundPackets"]+=1
        if initial:stats["externalInboundInitials"]+=1
        if short:stats["externalInboundShortHeaders"]+=1
stats.setdefault("externalInboundInitials",0)
print(json.dumps({"summary":stats,"externalFlows":flows},indent=2))
assert stats["loopbackInitials"]>0 and stats["externalInboundShortHeaders"]>0
assert stats["externalInboundInitials"]==0,"found a direct UDP Initial"
