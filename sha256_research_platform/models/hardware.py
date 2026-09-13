"""
Hardware and Environment Probing for iGPU-First Operation.
Detects CPU features, Vulkan compute devices, driver versions, and memory budget.
"""

import os
import platform
import subprocess
import psutil
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List


@dataclass
class HardwareProfile:
    cpu_model: str
    cpu_cores: int
    cpu_threads: int
    total_ram_bytes: int
    available_ram_bytes: int
    vulkan_available: bool
    vulkan_device_name: Optional[str] = None
    vulkan_driver_version: Optional[str] = None
    vulkan_api_version: Optional[str] = None
    vulkan_device_type: Optional[str] = None
    igpu_detected: bool = False
    conservative_memory_budget_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def probe_hardware() -> HardwareProfile:
    """Probes system hardware, Vulkan devices, and computes memory budget."""
    cpu_model = platform.processor() or "Generic x86_64"
    cpu_cores = os.cpu_count() or 4
    cpu_threads = psutil.cpu_count(logical=True) or cpu_cores

    mem = psutil.virtual_memory()
    total_ram = mem.total
    available_ram = mem.available

    # Probe Vulkan
    vulkan_available = False
    vulkan_dev_name = None
    vulkan_driver = None
    vulkan_api = None
    vulkan_type = None
    igpu_detected = False

    try:
        proc = subprocess.run(
            ["vulkaninfo", "--summary"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if proc.returncode == 0:
            vulkan_available = True
            lines = proc.stdout.splitlines()
            for line in lines:
                line_s = line.strip()
                if "deviceName" in line_s and "=" in line_s:
                    vulkan_dev_name = line_s.split("=")[1].strip()
                elif "driverVersion" in line_s and "=" in line_s:
                    vulkan_driver = line_s.split("=")[1].strip()
                elif "apiVersion" in line_s and "=" in line_s and not vulkan_api:
                    vulkan_api = line_s.split("=")[1].strip()
                elif "deviceType" in line_s and "=" in line_s:
                    vulkan_type = line_s.split("=")[1].strip()
                    if "INTEGRATED" in vulkan_type:
                        igpu_detected = True
    except Exception:
        pass

    # iGPU conservative memory budget:
    # On iGPU machines with shared memory, limit model memory to 40% of available RAM, max 4GB
    if igpu_detected or (vulkan_dev_name and "Radeon" in vulkan_dev_name):
        igpu_detected = True
        max_budget = 4 * 1024 * 1024 * 1024  # 4 GB max
        budget = min(int(available_ram * 0.40), max_budget)
    else:
        budget = min(int(available_ram * 0.50), 8 * 1024 * 1024 * 1024)

    return HardwareProfile(
        cpu_model=cpu_model,
        cpu_cores=cpu_cores,
        cpu_threads=cpu_threads,
        total_ram_bytes=total_ram,
        available_ram_bytes=available_ram,
        vulkan_available=vulkan_available,
        vulkan_device_name=vulkan_dev_name,
        vulkan_driver_version=vulkan_driver,
        vulkan_api_version=vulkan_api,
        vulkan_device_type=vulkan_type,
        igpu_detected=igpu_detected,
        conservative_memory_budget_bytes=budget
    )
