import socket
import struct

from typing import Tuple
LISTENING_PORT = 6200 
REQUEST_PORT = 5353
SERVER_IP = "" #BIAR BISA NGEBIND KE SEMUA IP, ALIAS NERIMA IPV4 MANA AJ
DNS_SERVER = "34.101.92.60" #IP SERVER ASDOS
BUFFER_SIZE = 2048

def request_parser(request_message_raw: bytearray, source_address: Tuple[str, int]) -> str:
    # Put your request message decoding logic here.
    # This method return a str.
    # Anda boleh menambahkan helper fungsi/method sebanyak yang Anda butuhkan selama 
    # TIDAK MENGUBAH ATAUPUN MENGHAPUS SPEC (parameter dan return type) YANG DIMINTA.
    id= struct.unpack("!H", request_message_raw[0:2])[0]
    qr = (request_message_raw[2]&int('10000000',2))>>7
    opcode = (request_message_raw[2]& int('01111000', 2))>>3
    aa = (request_message_raw[2]& int('00000100', 2))>>2
    tc = (request_message_raw[2]& int('00000010', 2))>>1
    rd = request_message_raw[2]& int('00000001',2)
    ra = (request_message_raw[3]& int('10000000',2))>>7
    z = (request_message_raw[3]& int('01000000',2))>>6
    ad = (request_message_raw[3]& int('00100000',2))>>5
    cd = (request_message_raw[3]& int('00010000',2))>>4
    rcode = request_message_raw[3]& int('00001111',2)
    qdcount = struct.unpack("!H",request_message_raw[4:6])[0]
    ancount = struct.unpack("!H",request_message_raw[6:8])[0]
    nscount = struct.unpack("!H",request_message_raw[8:10])[0]
    arcount = struct.unpack("!H",request_message_raw[10:12])[0]        
    qname = ""
    i = 12
    pointer = request_message_raw[i:i+1]
    while(pointer!=b'\x00'):
        if(pointer.decode().isalpha()):
            qname+=pointer.decode()
        elif(i>12):
            qname+="."
        i+=1
        pointer = request_message_raw[i:i+1]
    i=i+1
    qtype= struct.unpack("!H",request_message_raw[i:i+2])[0]
    i=i+2
    qclass= struct.unpack("!H",request_message_raw[i:i+2])[0]

    res = "=========================================================================\n[Request from ('{ip}', {port})]\n-------------------------------------------------------------------------\nHEADERS\nRequest ID: {id}\nQR: {qr} | OPCODE: {opcode} | AA: {aa} | TC: {tc} | RD: {rd} | RA: {ra} | AD: {ad} | CD: {cd} | RCODE: {rcode}\nQuestion Count: {qdcount} | Answer Count: {ancount} | Authority Count: {nscount} | Additional Count: {arcount}\n-------------------------------------------------------------------------\nQUESTION\nDomain Name: {qname} | QTYPE: {qtype} | QCLASS: {qclass}\n-------------------------------------------------------------------------\n".format(ip=source_address[0], port=source_address[1], id=id, qr=qr, opcode=opcode, aa=aa, tc=tc, rd=rd, ra=ra, ad=ad, cd=cd, rcode=rcode, qdcount=qdcount, ancount=ancount, nscount=nscount, arcount=arcount, qname=qname, qtype=qtype, qclass=qclass)
    return res


def response_parser(response_mesage_raw: bytearray) -> str:
    # Put your request message decoding logic here.
    # This method return a str.
    # Anda boleh menambahkan helper fungsi/method sebanyak yang Anda butuhkan selama 
    # TIDAK MENGUBAH ATAUPUN MENGHAPUS  SPEC (parameter dan return type) YANG DIMINTA.
    id= struct.unpack("!H", response_mesage_raw[0:2])[0]
    qr = (response_mesage_raw[2]&int('10000000',2))>>7
    opcode = (response_mesage_raw[2]& int('01111000', 2))>>3
    aa = (response_mesage_raw[2]& int('00000100', 2))>>2
    tc = (response_mesage_raw[2]& int('00000010', 2))>>1
    rd = response_mesage_raw[2]& int('00000001',2)
    ra = (response_mesage_raw[3]& int('10000000',2))>>7
    z = (response_mesage_raw[3]& int('01000000',2))>>6
    ad = (response_mesage_raw[3]& int('00100000',2))>>5
    cd = (response_mesage_raw[3]& int('00010000',2))>>4
    rcode = response_mesage_raw[3]& int('00001111',2)
    qdcount = struct.unpack("!H",response_mesage_raw[4:6])[0]
    ancount = struct.unpack("!H",response_mesage_raw[6:8])[0]
    nscount = struct.unpack("!H",response_mesage_raw[8:10])[0]
    arcount = struct.unpack("!H",response_mesage_raw[10:12])[0]       
    qname = ""
    i = 12
    pointer = response_mesage_raw[i:i+1]
    while(pointer!=b'\x00'):
        if(pointer.decode().isalpha()):
            qname+=pointer.decode()
        elif(i>12):
            qname+="."
        i+=1
        pointer = response_mesage_raw[i:i+1]
    i=i+1
    qtype= struct.unpack("!H",response_mesage_raw[i:i+2])[0]
    i=i+2
    qclass= struct.unpack("!H",response_mesage_raw[i:i+2])[0]
    i=i+2
    offset = response_mesage_raw[i+1]
    i=i+2
    type = struct.unpack("!H",response_mesage_raw[i:i+2])[0]
    i=i+2
    class_ = struct.unpack("!H",response_mesage_raw[i:i+2])[0]
    i=i+2
    ttl = struct.unpack("!L",response_mesage_raw[i:i+4])[0]
    i=i+4
    rdl=struct.unpack("!H",response_mesage_raw[i:i+2])[0]
    i=i+2
    rdata = "" #jawaban ipnya
    for j in range(0,rdl):
        ip_tmp=struct.unpack("!B",response_mesage_raw[i+j:i+j+1])[0]
        rdata+=str(ip_tmp)
        if(j<rdl-1):
            rdata+='.'


    string = "[Response from DNS Server]\n-------------------------------------------------------------------------\nHEADERS\nRequest ID: {id}\nQR: {qr} | OPCODE: {opcode} | AA: {aa} | TC: {tc} | RD: {rd} | RA: {ra} | AD: {ad} | CD: {cd} | RCODE: {rcode}\nQuestion Count: {qdcount} | Answer Count: {ancount} | Authority Count: {nscount} | Additional Count: {arcount}\n-------------------------------------------------------------------------\nQUESTION\nDomain Name: {qname} | QTYPE: {qtype} | QCLASS: {qclass}\n-------------------------------------------------------------------------\nANSWER\nTYPE: {type} | CLASS: {class_} | TTL: {ttl} | RDLENGTH: {rdl}\nIP Address: {rdata}\n==========================================================================".format(id=id, qr=qr, opcode=opcode, aa=aa, tc=tc, rd=rd, ra=ra, ad=ad, cd=cd, rcode=rcode, qdcount=qdcount, ancount=ancount, nscount=nscount, arcount=arcount, qname=qname, qtype=qtype, qclass=qclass, type=type, class_=class_, ttl=ttl, rdl=rdl, rdata=rdata)
    return string


def main():
    # Put the rest of your program's logic here (socket etc.). 
    # Pastikan blok socket Anda berada pada fungsi ini.

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((SERVER_IP, LISTENING_PORT))
        while True:
            request_message_raw, client_address = s.recvfrom(BUFFER_SIZE)
    

            s.sendto(request_message_raw, (DNS_SERVER, REQUEST_PORT))
            respond_mesage_raw, asdos_address = s.recvfrom(BUFFER_SIZE)


            s.sendto(respond_mesage_raw, client_address)

   
# DO NOT ERASE THIS PART!
if __name__ == "__main__":
    main() 