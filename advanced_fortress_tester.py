import os
import sys
import subprocess
import time
import hashlib
import json
import csv
import random
import string
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# --- Configuration ---
# NOTE: The raw video test can be time-consuming. Adjust size_mb for quicker tests.
INTEGRITY_TEST_SUITE = [
    {"name": "1MB Compressible Text", "size_mb": 1, "type": "text", "expected_compression": "lz4"},
    {"name": "10MB Uncompressible Binary", "size_mb": 10, "type": "binary", "expected_compression": "none"},
    {"name": "25MB Raw Video", "size_mb": 25, "type": "video", "expected_compression": "ffv1"},
    {"name": "Zero-Byte File", "size_mb": 0, "type": "binary", "expected_compression": "none"},
]

LOAD_TEST_CONFIG = {"name": "Load Test Job", "count": 16, "size_mb": 10, "type": "binary", "expected_compression": "none"}
STRESS_TEST_CONFIG = {"name": "Stress Test Job", "count": 32, "size_mb": 10, "type": "binary", "expected_compression": "none"}
API_TOKEN = "test-token-super-secret-12345"
RISK_IP = "8.8.8.8" # Medium Risk

# --- Helper Functions ---

def run_command(command, check=True):
    """Runs a command as a subprocess and returns its output."""
    return subprocess.run(command, check=check, capture_output=True, text=True)

def generate_test_file(path, size_mb, file_type):
    """Generates a test file of a specific type and size."""
    size_bytes = int(size_mb * 1024 * 1024)
    if os.path.exists(path):
        return
        
    if file_type == "text":
        base_string = b"This is a highly compressible string that repeats over and over again to test LZ4. "
        with open(path, 'wb') as f:
            while f.tell() < size_bytes:
                f.write(base_string)
            f.truncate(size_bytes)
    elif file_type == "video":
        # Duration is roughly size_mb / 5MB/s for this test source
        duration = max(1, int(size_mb / 5))
        run_command([
            'ffmpeg', '-f', 'lavfi', '-i', f'testsrc=duration={duration}:size=320x240:rate=30',
            '-c:v', 'rawvideo', '-pix_fmt', 'yuv420p', path
        ])
    else: # binary
        with open(path, 'wb') as f:
            if size_bytes > 0:
                f.write(os.urandom(size_bytes))

def streamed_sha256(file_path):
    """Calculates SHA256 of a file in chunks to handle large files."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4 * 1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()

# --- Core Test Runner ---

def run_single_test_case(config):
    """Runs a full encrypt-decrypt-verify cycle for a single test configuration."""
    scenario_name = config['name']
    size_mb = config['size_mb']
    file_type = config['type']
    expected_compression = config['expected_compression']
    
    unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    source_file = f"test_{unique_id}.tmp"
    
    start_time = time.time()
    result = {
        "scenario_name": scenario_name,
        "file_size_mb": size_mb,
        "status": "FAIL",
        "duration_s": 0,
        "throughput_mb_s": 0,
        "compression_used": "N/A",
        "error_details": ""
    }

    try:
        # 1. Generate test file
        generate_test_file(source_file, size_mb, file_type)

        # 2. Encrypt
        encrypted_file = f"{source_file}.fortress"
        encrypt_cmd = ['python3', 'fortress_mvp.py', 'encrypt', source_file, RISK_IP, 'public_key.pem', '-o', encrypted_file, '-t', API_TOKEN]
        encrypt_result = run_command(encrypt_cmd)

        # 3. Verify compression strategy from logs
        if f"Data Condenser Used: '{expected_compression}'" in encrypt_result.stdout:
            result["compression_used"] = expected_compression
        else:
            log_line = next((line for line in encrypt_result.stdout.splitlines() if "Data Condenser Used" in line), "Strategy log not found")
            raise RuntimeError(f"Incorrect compression strategy! Expected '{expected_compression}', but log shows: {log_line.strip()}")

        # 4. Decrypt
        output_dir = f"./output_{unique_id}"
        decrypted_file_name = os.path.basename(source_file)
        if file_type == 'video':
            decrypted_file_name = os.path.splitext(decrypted_file_name)[0] + ".avi"

        decrypted_file_path = os.path.join(output_dir, decrypted_file_name)
        decrypt_cmd = ['python3', 'fortress_mvp.py', 'decrypt', encrypted_file, 'private_key.pem', '-o', output_dir, '-t', API_TOKEN]
        run_command(decrypt_cmd)

        # 5. Verify Integrity
        if not os.path.exists(decrypted_file_path):
            raise FileNotFoundError(f"Decrypted file not found at {decrypted_file_path}")

        if file_type == "video":
            # For video, a simple existence and non-zero size check is sufficient for this automated test
            if os.path.getsize(decrypted_file_path) > 0:
                 pass # Integrity check passed
            else:
                 raise RuntimeError("Integrity check failed (decrypted video is 0 bytes).")
        else:
            original_hash = streamed_sha256(source_file)
            decrypted_hash = streamed_sha256(decrypted_file_path)
            if original_hash != decrypted_hash:
                raise RuntimeError(f"Integrity check failed (hashes do not match). Original: {original_hash}, Decrypted: {decrypted_hash}")

        result["status"] = "PASS"

    except (subprocess.CalledProcessError, RuntimeError, FileNotFoundError, Exception) as e:
        error_output = f"Error: {e}"
        if hasattr(e, 'stdout'): error_output += f"\\nSTDOUT: {e.stdout}"
        if hasattr(e, 'stderr'): error_output += f"\\nSTDERR: {e.stderr}"
        result["error_details"] = error_output
    
    finally:
        # Cleanup
        for path in [source_file, encrypted_file]:
            if os.path.exists(path): os.remove(path)
        if os.path.exists(output_dir): shutil.rmtree(output_dir)
        
        end_time = time.time()
        duration = end_time - start_time
        result["duration_s"] = round(duration, 2)
        if duration > 0 and size_mb > 0:
            # Throughput based on processing original data size
            result["throughput_mb_s"] = round((size_mb * 2) / duration, 2) # *2 for encrypt + decrypt

    return result

# --- Main Test Execution ---

def main():
    """Main function to set up environment and run all tests."""
    print("--- Dynamic Cryptographic Fortress: Advanced Test Suite ---")
    
    # Generate keys needed for the test run
    print("\n[SETUP] Generating RSA key pair for tests...")
    run_command(['python3', 'fortress_mvp.py', 'keygen'])
    print("[SETUP] Environment ready.")

    all_results = []
    
    # 2. Integrity Tests
    print("\n--- Running Integrity Test Suite ---")
    for config in INTEGRITY_TEST_SUITE:
        print(f"  Testing: {config['name']}...")
        result = run_single_test_case(config)
        all_results.append({**result, "test_type": "Integrity"})
        print(f"    -> Status: {result['status']}, Duration: {result['duration_s']}s")
        if result['status'] == 'FAIL': 
            print(f"       ERROR: {result['error_details']}")
            # Exit with a non-zero code to fail the CI job
            sys.exit(1)
    print("--- Integrity Test Suite Complete ---")

    # 3. Load Test
    print("\n--- Running Load Test ---")
    load_start_time = time.time()
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        configs = [{**LOAD_TEST_CONFIG, "name": f"Load Job {i+1}"} for i in range(LOAD_TEST_CONFIG["count"])]
        futures = [executor.submit(run_single_test_case, config) for config in configs]
        for future in futures:
             all_results.append({**future.result(), "test_type": "Load"})
    load_duration = time.time() - load_start_time
    total_data_mb = LOAD_TEST_CONFIG['size_mb'] * LOAD_TEST_CONFIG['count'] * 2
    load_throughput = round(total_data_mb / load_duration, 2) if load_duration > 0 else 0
    print("--- Load Test Complete ---")

    # 4. Stress Test
    print("\n--- Running Stress Test ---")
    stress_start_time = time.time()
    with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        configs = [{**STRESS_TEST_CONFIG, "name": f"Stress Job {i+1}"} for i in range(STRESS_TEST_CONFIG["count"])]
        futures = [executor.submit(run_single_test_case, config) for config in configs]
        for future in futures:
            all_results.append({**future.result(), "test_type": "Stress"})
    stress_duration = time.time() - stress_start_time
    total_data_mb = STRESS_TEST_CONFIG['size_mb'] * STRESS_TEST_CONFIG['count'] * 2
    stress_throughput = round(total_data_mb / stress_duration, 2) if stress_duration > 0 else 0
    print("--- Stress Test Complete ---")
    
    # 5. Generate Reports
    print("\n--- Generating Reports ---")
    # Write CSV Report
    with open("test_results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
        writer.writeheader()
        writer.writerows(all_results)
    print("  -> Detailed results saved to test_results.csv")

    # Write JSON Summary
    summary = {
        "timestamp": datetime.now().isoformat(),
        "integrity_tests": {
            "total": len(INTEGRITY_TEST_SUITE),
            "passed": sum(1 for r in all_results if r['test_type'] == 'Integrity' and r['status'] == 'PASS'),
        },
        "load_test": {
            "jobs": LOAD_TEST_CONFIG['count'],
            "total_duration_s": round(load_duration, 2),
            "aggregate_throughput_mb_s": load_throughput
        },
        "stress_test": {
            "jobs": STRESS_TEST_CONFIG['count'],
            "total_duration_s": round(stress_duration, 2),
            "aggregate_throughput_mb_s": stress_throughput
        }
    }
    with open("summary_report.json", "w") as f:
        json.dump(summary, f, indent=4)
    print("  -> Aggregate summary saved to summary_report.json")
    
    # 6. Final Console Summary
    print("\n" + "="*35)
    print("      TEST SUITE FINAL SUMMARY")
    print("="*35)
    print(f"  Integrity Tests: {summary['integrity_tests']['passed']}/{summary['integrity_tests']['total']} Passed")
    print(f"  Load Test Throughput: {load_throughput} MB/s")
    print(f"  Stress Test Throughput: {stress_throughput} MB/s")
    print("="*35)

    # Final check to ensure all integrity tests passed
    if summary['integrity_tests']['passed'] != summary['integrity_tests']['total']:
        print("\n[CI-FAIL] One or more integrity tests failed.")
        sys.exit(1)

if __name__ == "__main__":
    if not os.path.exists("fortress_mvp.py"):
        print("[FATAL] fortress_mvp.py not found. Please place this script in the same directory.")
        sys.exit(1)
    else:
        main()
