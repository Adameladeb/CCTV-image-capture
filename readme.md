# 📌 CCTV Capture Script

The CCTV Capture Script is a Python application designed to scan a local network for CCTV cameras, capture network traffic from these cameras, and extract real images from the captured data. The script uses Nmap for network scanning, Scapy for packet sniffing, and PyShark for parsing and extracting images.

## 📝 Requirements

- Python 3.x
- Nmap
- Scapy
- PyShark
- A network with CCTV cameras connected

## 🚀 Getting Started

1. Clone this repository to your local machine.
2. Install the required dependencies using `pip`:


3. Configure the script:
- Specify the CCTV ports you want to monitor in the `CCTV_PORTS` list.
- Set the subnet to scan for CCTV cameras in the `SUBNET` variable.
- Add any desired image formats to the `IMAGE_FORMATS` list.

4. Run the script:

`python main.py`



## 🔍 Network Scan

The script will start by scanning the specified subnet for CCTV cameras on the designated ports. If any CCTV cameras are detected, their IP addresses and open ports will be displayed.

## 📷 Capture Images

The script will then capture network traffic from the identified CCTV cameras and store it in a PCAP file named `captured_images.pcap`.

## 🎥 Extract Real Images

After capturing network traffic, the script will extract real images from the captured data. These images will be saved in the `captured_images` directory. Images matching the specified image formats will be identified, and their filenames will be in the format `real_captured_<number>.<format>`.

## 💡 Tips

- Ensure that you have the necessary permissions (sudo) to run Nmap and capture network traffic.
- Make sure to have CCTV cameras active on the network with accessible image data.
- Check the log files for any errors or issues during the capture process.

## 🛑 Stopping the Capture

To stop the capture process, press `Ctrl + C`.

## 📂 Captured Images

The extracted images will be saved in the `captured_images` directory. This directory will be automatically created if it does not exist.

## 📝 Note

Please try to fix this shit this script is fucked up so bad just pull a request pls 🥺

## 🚧 Disclaimer

No disclaimer lol use this script whenever u want.

## 📧 Contact

For any questions, issues, or feedback, please contact [idevsenior@gmail.com].

Happy CCTV capturing! 📹📸

