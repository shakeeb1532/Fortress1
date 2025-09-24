import os
import json
import time
import hashlib
import argparse
import random
import shutil
import subprocess # --- CHANGE: Added for running FFmpeg
from datetime import datetime
from base64 import b64encode, b64decode

# --- Production-Grade Dependencies ---
# System Prerequisite: FFmpeg (install via brew, choco, or apt)
# Python Packages: pip install pycryptodome lz4
from Cryptodome.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from lz4.frame import LZ4FrameCompressor, LZ4FrameDecompressor, compress

# --- All Classes Consolidated for a Production-Ready Tool ---

class SecurityException(Exception):
    """Custom exception for security-related failures."""
    pass

class SecureAI_API_Simulator:
    """Simulates the hardened, server-side AI model."""
    def __init__(self):
        # (Knowledge base and threat intel remain the same)
        self.knowledge_base = {
            "8.8.8.8": [{"source": "CFR", "risk": 3.0, "type": "State-Sponsored Activity"}],
            "45.33.32.156": [{"source": "ACSC", "risk": 2.5, "type": "Malware Host"}],
            "10.0.0.5": [{"source": "PRC", "risk": 1.0, "type": "Minor Data Breach (Past)"}],
            "118.25.6.39": [{"source": "Mandiant", "risk": 7.0, "type": "APT41 Infrastructure"}],
            "216.3.128.12": [{"source": "ZDI", "risk": 8.0, "type": "Zero-Day Exploit Host"}]
        }
        self.threat_intel = {
            "192.168.1.10": {"baseRisk": 1}, "10.0.0.5": {"baseRisk": 4},
            "8.8.8.8": {"baseRisk": 5}, "45.33.32.156": {"baseRisk": 6},
            "118.25.6.39": {"baseRisk": 8}, "216.3.128.12": {"baseRisk": 9}
        }
        self.cipher_pools = {"standard": ['AES-GCM', 'ChaCha20-Poly1305'], "hardened": ['AES-GCM', 'ChaCha20-Poly1305']}
        self.risk_profiles = [
            (3, {"profile": "low_risk", "layers": 2, "pool": "standard"}),
            (6, {"profile": "medium_risk", "layers": 3, "pool": "standard"}),
            (8, {"profile": "high_risk", "layers": 3, "pool": "hardened"}),
            (10, {"profile": "extreme_risk", "layers": 4, "pool": "hardened"})
        ]
    
    # --- CHANGE: AI now accepts source_path to determine compression strategy ---
    def get_encryption_recipe(self, api_token: str, destination_ip: str, source_path: str) -> dict:
        if not api_token or len(api_token) < 16: raise SecurityException("AI Auth Failure: Invalid or missing API token.")
        if destination_ip not in self.threat_intel: raise ValueError(f"Unknown IP: {destination_ip}")
        
        intel = self.threat_intel[destination_ip]
        historical_risk = sum(item['risk'] for item in self.knowledge_base.get(destination_ip, []))
        risk_score = min(intel["baseRisk"] + historical_risk, 10)
        
        profile_template = next(template for threshold, template in self.risk_profiles if risk_score <= threshold)
        recipe = {"profile": profile_template["profile"], "layers": []}
        selected_algos = random.choices(self.cipher_pools[profile_template["pool"]], k=profile_template["layers"])
        
        for algo in selected_algos:
            recipe["layers"].append({"algorithm": algo, "key": b64encode(get_random_bytes(32)).decode('ascii')})
        
        # --- CHANGE: AI now sets the compression strategy based on file type ---
        file_extension = os.path.splitext(source_path)[1].lower()
        if file_extension in ['.y4m', '.avi']: # Common raw video formats
             recipe['compression_strategy'] = 'lossless_video_ffv1'
        else:
             recipe['compression_strategy'] = 'standard_lz4' # Default strategy

        return {"recipe": recipe, "assessment": f"Risk: {risk_score:.1f}/10.0 -> Profile: '{recipe['profile']}'"}

class DataCondenser:
    """Handles intelligent, high-speed data compression based on a given strategy."""
    def __init__(self):
        self.segment_size = 16 * 1024 * 1024
        self.COMPRESSION_RATIO_THRESHOLD = 0.05

    def _should_compress_with_lz4(self, file_path: str) -> bool:
        with open(file_path, 'rb') as f:
            first_chunk = f.read(256 * 1024)
        if not first_chunk: return False
        return (1.0 - (len(compress(first_chunk)) / len(first_chunk))) >= self.COMPRESSION_RATIO_THRESHOLD

    # --- CHANGE: New private method for FFmpeg compression ---
    def _compress_with_ffmpeg(self, source_path: str, dest_path: str):
        self._log("Using FFmpeg for lossless video compression...")
        # Using .mkv container as it's excellent for FFV1. Stripping audio (-an) for focus on video data.
        command = [
            'ffmpeg', '-y', '-i', source_path,
            '-c:v', 'ffv1', '-level', '3', '-g', '1', '-an',
            dest_path
        ]
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            self._log("FFmpeg compression successful.")
        except FileNotFoundError:
            raise RuntimeError("FFmpeg not found. Please ensure FFmpeg is installed and in your system's PATH.")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"FFmpeg failed to compress file. Error: {e.stderr}")

    def _compress_with_lz4(self, source_path: str, dest_path: str):
        with open(source_path, 'rb') as f_in, open(dest_path, 'wb') as f_out:
            compressor = LZ4FrameCompressor()
            f_out.write(compressor.begin())
            while chunk := f_in.read(self.segment_size):
                f_out.write(compressor.compress(chunk))
            f_out.write(compressor.flush())

    # --- CHANGE: compress_stream is now a dispatcher based on strategy ---
    def compress_stream(self, source_path: str, dest_path: str, strategy: str) -> str:
        if strategy == 'lossless_video_ffv1':
            self._compress_with_ffmpeg(source_path, dest_path)
            return 'ffv1'
        
        # Default to standard_lz4 logic
        if self._should_compress_with_lz4(source_path):
            self._compress_with_lz4(source_path, dest_path)
            return 'lz4'
        else:
            shutil.copyfile(source_path, dest_path)
            return 'none'
    
    # --- CHANGE: New private method for FFmpeg decompression ---
    def _decompress_with_ffmpeg(self, source_path: str, dest_path: str):
        self._log("Using FFmpeg for lossless video decompression...")
        # We decompress back to a raw format container like AVI for interchangeability.
        command = ['ffmpeg', '-y', '-i', source_path, '-c', 'copy', dest_path]
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
            self._log("FFmpeg decompression successful.")
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            raise RuntimeError(f"FFmpeg failed to decompress file. Error: {getattr(e, 'stderr', e)}")

    # --- CHANGE: decompress_stream is now a dispatcher ---
    def decompress_stream(self, source_path: str, dest_path: str, strategy: str):
        if strategy == 'ffv1':
            self._decompress_with_ffmpeg(source_path, dest_path)
        elif strategy == 'lz4':
            with open(source_path, 'rb') as f_in, open(dest_path, 'wb') as f_out:
                decompressor = LZ4FrameDecompressor()
                while chunk := f_in.read(self.segment_size):
                    f_out.write(decompressor.decompress(chunk))
        else: # 'none'
            # If there was no compression, the temp file is the final file.
            # The calling function will handle moving it.
            pass

    def _log(self, message):
         print(f"[{datetime.now().isoformat(sep=' ', timespec='seconds')}] [DataCondenser] {message}")


class CryptoEngine:
    """Handles the actual cryptographic operations."""
    def encrypt(self, plaintext: bytes, layer_recipe: dict) -> bytes:
        algo, key = layer_recipe['algorithm'], b64decode(layer_recipe['key'])
        nonce_size = 16 if algo == 'AES-GCM' else 24
        nonce = get_random_bytes(nonce_size)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce) if algo == 'AES-GCM' else ChaCha20_Poly1305.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ciphertext + tag
    
    def decrypt(self, ciphertext: bytes, layer_recipe: dict) -> bytes:
        algo, key = layer_recipe['algorithm'], b64decode(layer_recipe['key'])
        nonce_size, tag_size = (16, 16) if algo == 'AES-GCM' else (24, 16)
        nonce, encrypted_data, tag = ciphertext[:nonce_size], ciphertext[nonce_size:-tag_size], ciphertext[-tag_size:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce) if algo == 'AES-GCM' else ChaCha20_Poly1305.new(key=key, nonce=nonce)
        return cipher.decrypt_and_verify(encrypted_data, tag)

class DynamicCryptographicFortress:
    """The main application engine, re-architected for streaming and security."""
    def __init__(self, api_token: str):
        self.ai_api = SecureAI_API_Simulator()
        self.condenser = DataCondenser()
        self.crypto_engine = CryptoEngine()
        self.api_token = api_token

    def _log(self, message):
        print(f"[{datetime.now().isoformat(sep=' ', timespec='seconds')}] {message}")

    def encrypt_file(self, source_path: str, dest_path: str, destination_ip: str, recipient_pub_key_path: str):
        self._log(f"Starting encryption for '{source_path}'...")
        start_time = time.time()
        
        # --- CHANGE: Pass source_path to AI for analysis ---
        decision = self.ai_api.get_encryption_recipe(self.api_token, destination_ip, source_path)
        recipe = decision["recipe"]
        self._log(f"AI Decision: {decision['assessment']}")
        
        temp_path = source_path + ".tmp"
        
        # --- CHANGE: Use the compression strategy from the AI ---
        compression_type_used = self.condenser.compress_stream(source_path, temp_path, recipe['compression_strategy'])
        recipe['compression_type'] = compression_type_used # Store what was actually used
        self._log(f"Data Condenser Used: '{compression_type_used}'")
        
        # (Asymmetric header encryption remains the same)
        recipe['originalFileName'] = os.path.basename(source_path)
        recipe_json = json.dumps(recipe).encode('utf-8')
        
        recipe_session_key = get_random_bytes(32)
        recipe_cipher = AES.new(recipe_session_key, AES.MODE_GCM)
        encrypted_recipe, recipe_tag = recipe_cipher.encrypt_and_digest(recipe_json)
        
        with open(recipient_pub_key_path, 'rb') as f:
            recipient_key = RSA.import_key(f.read())
        rsa_cipher = PKCS1_OAEP.new(recipient_key)
        encrypted_session_key = rsa_cipher.encrypt(recipe_session_key)

        with open(temp_path, 'rb') as f_in, open(dest_path, 'wb') as f_out:
            # Write header
            f_out.write(len(encrypted_session_key).to_bytes(2, 'big'))
            f_out.write(encrypted_session_key)
            f_out.write(recipe_cipher.nonce)
            f_out.write(recipe_tag)
            f_out.write(len(encrypted_recipe).to_bytes(4, 'big'))
            f_out.write(encrypted_recipe)
            
            # (Self-describing chunk logic remains the same)
            while chunk := f_in.read(self.condenser.segment_size):
                processed_chunk = chunk
                for layer in recipe["layers"]:
                    processed_chunk = self.crypto_engine.encrypt(processed_chunk, layer)
                f_out.write(len(processed_chunk).to_bytes(4, 'big'))
                f_out.write(processed_chunk)

        os.remove(temp_path)
        self._log(f"Encryption complete in {time.time() - start_time:.2f} seconds. Output: {dest_path}")

    def decrypt_file(self, source_path: str, dest_dir: str, private_key_path: str):
        self._log(f"Starting decryption for '{source_path}'...")
        start_time = time.time()
        os.makedirs(dest_dir, exist_ok=True)
        
        with open(source_path, 'rb') as f_in:
            # (Header decryption remains the same)
            with open(private_key_path, 'rb') as f:
                private_key = RSA.import_key(f.read())
            rsa_cipher = PKCS1_OAEP.new(private_key)

            enc_session_key_len = int.from_bytes(f_in.read(2), 'big')
            encrypted_session_key = f_in.read(enc_session_key_len)
            recipe_nonce = f_in.read(16)
            recipe_tag = f_in.read(16)
            recipe_len = int.from_bytes(f_in.read(4), 'big')
            encrypted_recipe = f_in.read(recipe_len)
            
            recipe_session_key = rsa_cipher.decrypt(encrypted_session_key)
            
            recipe_cipher = AES.new(recipe_session_key, AES.MODE_GCM, nonce=recipe_nonce)
            recipe_json = recipe_cipher.decrypt_and_verify(encrypted_recipe, recipe_tag)
            recipe = json.loads(recipe_json.decode('utf-8'))
            self._log(f"Recipe decrypted. Profile: '{recipe['profile']}', Compression: '{recipe.get('compression_type', 'none')}'")

            final_path = os.path.join(dest_dir, recipe['originalFileName'])
            # --- CHANGE: Decompression needs to know the final path for FFmpeg ---
            # And we need a different temp path for the decrypted content before decompression
            decrypted_temp_path = final_path + ".decrypted.tmp"

            with open(decrypted_temp_path, 'wb') as f_out:
                while True:
                    chunk_len_bytes = f_in.read(4)
                    if not chunk_len_bytes: break
                    chunk_len = int.from_bytes(chunk_len_bytes, 'big')
                    chunk = f_in.read(chunk_len)
                    
                    processed_chunk = chunk
                    for layer in reversed(recipe["layers"]):
                        processed_chunk = self.crypto_engine.decrypt(processed_chunk, layer)
                    f_out.write(processed_chunk)
            
            compression_used = recipe.get('compression_type', 'none')
            if compression_used != 'none':
                self._log(f"Data Condenser: Decompressing file with '{compression_used}'...")
                # --- CHANGE: Pass strategy to decompress_stream ---
                # For FFmpeg, we decompress to the final path. For LZ4, it's the same.
                if compression_used == 'ffv1':
                    # FFmpeg needs a different extension for output, so we create a temp final output
                    final_video_path = os.path.splitext(final_path)[0] + ".avi"
                    self.condenser.decompress_stream(decrypted_temp_path, final_video_path, compression_used)
                else:
                    self.condenser.decompress_stream(decrypted_temp_path, final_path, compression_used)
                os.remove(decrypted_temp_path)
            else:
                shutil.move(decrypted_temp_path, final_path)
        
        self._log(f"Decryption complete in {time.time() - start_time:.2f} seconds.")

def generate_keys():
    """Generates a new RSA public/private key pair."""
    key = RSA.generate(4096)
    with open("private_key.pem", "wb") as f: f.write(key.export_key())
    with open("public_key.pem", "wb") as f: f.write(key.publickey().export_key())
    print("Generated 'private_key.pem' and 'public_key.pem'.")

def main():
    parser = argparse.ArgumentParser(description="Dynamic Cryptographic Fortress")
    parser.add_argument("-t", "--api-token", help="Secure API token (or set FORTRESS_API_TOKEN).")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("keygen", help="Generate a new public/private key pair.")
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file.")
    encrypt_parser.add_argument("source", help="Path to the source file.")
    encrypt_parser.add_argument("destination_ip", help="Target IP for risk assessment.")
    encrypt_parser.add_argument("recipient_key", help="Path to the recipient's public key (.pem).")
    encrypt_parser.add_argument("-o", "--output", help="Output file path.")
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file.")
    decrypt_parser.add_argument("source", help="Path to the .fortress file.")
    decrypt_parser.add_argument("private_key", help="Path to your private key (.pem).")
    decrypt_parser.add_argument("-o", "--output", help="Output directory.", default="./output")
    
    args = parser.parse_args()
    
    if args.command == "keygen":
        generate_keys()
        return

    api_token = args.api_token or os.environ.get("FORTRESS_API_TOKEN")
    if not api_token:
        print("[ERROR] No API token provided.")
        return

    fortress = DynamicCryptographicFortress(api_token=api_token)

    try:
        if args.command == "encrypt":
            output_path = args.output or args.source + ".fortress"
            fortress.encrypt_file(args.source, output_path, args.destination_ip, args.recipient_key)
        elif args.command == "decrypt":
            fortress.decrypt_file(args.source, args.output, args.private_key)
    except (FileNotFoundError, SecurityException, ValueError, RuntimeError) as e:
        print(f"\n[ERROR] Operation failed: {e}")
    except Exception as e:
        print(f"\n[UNEXPECTED FATAL ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()