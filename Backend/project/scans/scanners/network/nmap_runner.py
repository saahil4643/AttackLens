import subprocess
import shutil
import time
import os
import signal

class NmapRunner:
    def __init__(self, timeout=300):
        self.timeout = timeout
        self.process = None

    @classmethod
    def is_nmap_installed(cls) -> bool:
        """
        Checks if Nmap is available in the system PATH.
        """
        return shutil.which("nmap") is not None

    @classmethod
    def get_nmap_version(cls) -> str:
        """
        Queries Nmap to get its version string.
        """
        try:
            res = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout:
                first_line = res.stdout.splitlines()[0]
                return first_line
        except Exception:
            pass
        return "Unknown"

    def run_scan(self, target, port_range: str, cancel_check=None) -> dict:
        """
        Executes Nmap TCP connect scan (-sT) against one or more targets.
        Uses XML output format (-oX -).
        Supports periodic cancellation checks and execution timeout.
        
        Returns a dict:
        {
            "status": "success" | "failed" | "cancelled" | "timeout",
            "xml_output": str,
            "stderr": str,
            "error_message": str
        }
        """
        if not self.is_nmap_installed():
            return {
                "status": "failed",
                "xml_output": "",
                "stderr": "",
                "error_message": "Nmap is not installed or is unavailable on the AttackLens worker."
            }

        # Handle list of targets or single string
        if isinstance(target, str):
            targets = [target]
        else:
            targets = list(target)

        clean_targets = []
        for t in targets:
            clean_t = str(t).strip()
            if not clean_t:
                continue
            # Validate target to prevent command-injection/arbitrary arguments
            if clean_t.startswith("-") or " " in clean_t:
                return {
                    "status": "failed",
                    "xml_output": "",
                    "stderr": "",
                    "error_message": f"Invalid or unsafe scan target: {clean_t}"
                }
            clean_targets.append(clean_t)

        if not clean_targets:
            return {
                "status": "failed",
                "xml_output": "",
                "stderr": "",
                "error_message": "No valid targets specified."
            }

        # Safe command argument array
        args = ["nmap", "-sT", "-p", port_range, "-oX", "-"] + clean_targets

        try:
            # CREATE_NEW_PROCESS_GROUP is useful on Windows to send break signals
            creation_flags = 0
            if os.name == 'nt':
                creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP

            self.process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=creation_flags
            )
        except Exception as e:
            return {
                "status": "failed",
                "xml_output": "",
                "stderr": "",
                "error_message": f"Failed to launch Nmap process: {str(e)}"
            }

        start_time = time.time()
        
        # We poll the process state in a loop
        while True:
            # Check if process finished
            ret = self.process.poll()
            if ret is not None:
                break

            # Check if cancelled externally
            if cancel_check and cancel_check():
                self.terminate_process()
                return {
                    "status": "cancelled",
                    "xml_output": "",
                    "stderr": "Scan cancelled by client.",
                    "error_message": "Scan cancelled."
                }

            # Check if timeout exceeded
            if time.time() - start_time > self.timeout:
                self.terminate_process()
                return {
                    "status": "timeout",
                    "xml_output": "",
                    "stderr": f"Scan timed out after {self.timeout}s.",
                    "error_message": f"Nmap scan timed out after {self.timeout} seconds."
                }

            time.sleep(0.5)

        # Process is finished, read outputs
        stdout, stderr = self.process.communicate()

        if self.process.returncode != 0:
            return {
                "status": "failed",
                "xml_output": stdout,
                "stderr": stderr,
                "error_message": f"Nmap exited with code {self.process.returncode}."
            }

        return {
            "status": "success",
            "xml_output": stdout,
            "stderr": stderr,
            "error_message": ""
        }

    def terminate_process(self):
        """
        Safely terminates the Nmap process.
        """
        if not self.process:
            return

        try:
            if os.name == 'nt':
                # Under Windows, send CTRL_BREAK to process group
                self.process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.process.terminate()
            self.process.wait(timeout=5)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass
