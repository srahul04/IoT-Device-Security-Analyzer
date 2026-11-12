#!/usr/bin/env python3
"""
Performance test script to demonstrate the speed improvements in IDSA.
This script compares the old sequential scanning with the new concurrent scanning.
"""

import time
import network_scanner
import system_scanner

def test_network_scan_performance():
    """Test network scanning performance."""
    print("=== Network Scan Performance Test ===")
    
    # Test old sequential method
    print("Testing old sequential network scan...")
    start_time = time.time()
    
    local_ip = network_scanner.get_local_ip()
    network_range = network_scanner.get_network_range(local_ip)
    active_hosts = network_scanner.ping_sweep(network_range)
    
    # Sequential port scanning
    for host in active_hosts[:3]:  # Limit to first 3 hosts for testing
        network_scanner.scan_open_ports(host)
    
    old_time = time.time() - start_time
    print(f"Old sequential method: {old_time:.2f} seconds")
    
    # Test new concurrent method
    print("Testing new concurrent network scan...")
    start_time = time.time()
    
    network_results = network_scanner.fast_network_scan()
    
    new_time = time.time() - start_time
    print(f"New concurrent method: {new_time:.2f} seconds")
    
    if old_time > 0:
        speedup = old_time / new_time
        print(f"Speed improvement: {speedup:.2f}x faster")
    
    print(f"Active hosts found: {len(network_results.get('active_hosts', []))}")
    print()

def test_system_scan_performance():
    """Test system scanning performance."""
    print("=== System Scan Performance Test ===")
    
    # Test old sequential method
    print("Testing old sequential system scan...")
    start_time = time.time()
    
    os_info = system_scanner.get_os_info()
    hostname = system_scanner.get_hostname()
    disk_usage = system_scanner.get_disk_usage("C:/" if __import__('os').name == "nt" else "/")
    users = system_scanner.get_logged_in_users()
    
    old_time = time.time() - start_time
    print(f"Old sequential method: {old_time:.2f} seconds")
    
    # Test new concurrent method
    print("Testing new concurrent system scan...")
    start_time = time.time()
    
    system_data = system_scanner.get_system_info_fast()
    
    new_time = time.time() - start_time
    print(f"New concurrent method: {new_time:.2f} seconds")
    
    if old_time > 0:
        speedup = old_time / new_time
        print(f"Speed improvement: {speedup:.2f}x faster")
    
    print()

def main():
    """Run all performance tests."""
    print("IDSA Performance Test")
    print("=" * 50)
    print()
    
    test_system_scan_performance()
    test_network_scan_performance()
    
    print("Performance test completed!")
    print("\nKey improvements:")
    print("- Concurrent network scanning with ThreadPoolExecutor")
    print("- Parallel system information gathering")
    print("- Reduced timeouts for faster response")
    print("- Real-time progress updates via queue system")
    print("- Non-blocking GUI with background processing")

if __name__ == "__main__":
    main()
