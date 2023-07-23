#please give me credits if you are going to use this shit

import os
import logging
import asyncio
import nmap
import pyshark
from scapy.all import *
from typing import List, Tuple

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")

CAPTURED_IMAGES_PCAP = 'captured_images.pcap'
CCTV_PORTS: List[int] = [554, 80]
SUBNET: str = "192.168.1.0/24"
IMAGE_FORMATS: List[str] = ["jpeg", "png", "gif", "jpg"]
CAPTURED_IMAGES_DIR: str = "captured_images"

if not os.path.exists(CAPTURED_IMAGES_DIR):
    os.makedirs(CAPTURED_IMAGES_DIR)

async def extract_image_from_packet(packet: Packet) -> None:
    """Extract an image from a packet and save it to a file."""
    if packet.haslayer(Raw):
        image_data = packet[Raw].load
        for image_format in IMAGE_FORMATS:
            if image_format.encode() in image_data:
                image_filename = f"captured_{len(os.listdir(CAPTURED_IMAGES_DIR)) + 1}.{image_format}"
                image_path = os.path.join(CAPTURED_IMAGES_DIR, image_filename)
                async with aiofiles.open(image_path, 'wb') as image_file:
                    await image_file.write(image_data)
                logging.info(f"Image captured and saved: {image_filename}")
                break

def network_scan(subnet: str) -> List[Tuple[str, dict]]:
    """Scan a network for CCTV cameras on specified ports."""
    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments='-p %s' % ','.join(map(str, CCTV_PORTS)))
    return [(x, scanner[x]['tcp']) for x in scanner.all_hosts() if scanner[x].state() == 'up']

async def run_cctv_capture() -> None:
    """Main function that runs the network scan and packet sniffer."""
    try:
        logging.info("Scanning network for CCTV cameras...")
        cameras = network_scan(SUBNET)
        logging.info(f"Found {len(cameras)} CCTV camera(s) on the network.")
        if not cameras:
            logging.warning("No CCTV cameras found on the network.")

        logging.info("Capturing images from CCTV traffic...")
        pcap_writer = PcapWriter(CAPTURED_IMAGES_PCAP, append=True)
        filter_expression = "tcp port " + " or tcp port ".join(map(str, CCTV_PORTS))
        sniff(filter=filter_expression, prn=pcap_writer.write, store=False)

        logging.info("Capturing complete. Extracting real images from the pcap file...")
        async with aiofiles.threadpool.AsyncTextIOWrapper(pyshark.FileCapture(CAPTURED_IMAGES_PCAP), 'rb') as pcap_file:
            pcap = pyshark.FileCapture(pcap_file)
            image_count = 0
            for packet in pcap:
                if 'Raw' in packet and packet.transport_layer == 'TCP' and packet.tcp.dstport in CCTV_PORTS:
                    payload = packet['Raw'].load
                    for image_format in IMAGE_FORMATS:
                        if image_format.encode() in payload:
                            image_filename = f"real_captured_{image_count + 1}.{image_format}"
                            image_path = os.path.join(CAPTURED_IMAGES_DIR, image_filename)
                            async with aiofiles.open(image_path, 'wb') as image_file:
                                await image_file.write(payload)
                            logging.info(f"Real image captured and saved: {image_filename}")
                            image_count += 1
                            break
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    try:
       asyncio.run(run_cctv_capture())
    except KeyboardInterrupt:
        logging.info("Capture stopped by the user.")
