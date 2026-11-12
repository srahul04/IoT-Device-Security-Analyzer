import platform
import subprocess
import re

def get_usb_devices():
    """Returns a list of connected USB devices (platform-dependent)."""
    devices = []
    if platform.system() == "Windows":
        try:
            # Using wmic command to get USB device information
            command = "wmic path Win32_PnPEntity where \"Caption like '%USB%'\" get Caption,DeviceID /format:list"
            result = subprocess.run(command, capture_output=True, text=True, check=True, shell=True)
            output = result.stdout

            current_device = {}
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Caption="):
                    if current_device:
                        devices.append(current_device)
                    current_device = {"Description": line.replace("Caption=", "").strip(), "DeviceID": ""}
                elif line.startswith("DeviceID="):
                    if current_device:
                        current_device["DeviceID"] = line.replace("DeviceID=", "").strip()
            if current_device:
                devices.append(current_device)

        except Exception as e:
            devices.append({"Error": f"Error getting Windows USB devices: {e}"})
    elif platform.system() == "Linux":
        try:
            # Using lsusb command to get USB device information
            result = subprocess.run(["lsusb"], capture_output=True, text=True, check=True)
            output = result.stdout
            for line in output.splitlines():
                match = re.search(r'Bus (\w+) Device (\w+): ID (\w+:\w+) (.*)', line)
                if match:
                    bus = match.group(1)
                    device = match.group(2)
                    id_vendor_product = match.group(3)
                    description = match.group(4)
                    devices.append({
                        "Bus": bus,
                        "Device": device,
                        "ID": id_vendor_product,
                        "Description": description.strip()
                    })
                else:
                    devices.append({"Raw": line.strip()}) # Fallback for unparsed lines
        except FileNotFoundError:
            devices.append({"Error": "lsusb command not found. Please install usbutils (e.g., sudo apt-get install usbutils)."})
        except Exception as e:
            devices.append({"Error": f"Error getting Linux USB devices: {e}"})
    else:
        devices.append({"Error": "USB enumeration not supported on this OS."})
    return devices

# Example Usage:
if __name__ == "__main__":
    usb_devices = get_usb_devices()
    if usb_devices:
        for device in usb_devices:
            print(device)
    else:
        print("No USB devices found or unable to retrieve.")
