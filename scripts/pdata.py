import json
import os

def load_config(file_path):
    if not os.path.exists(file_path):
        print(f"Bruh, {file_path} not found. Default config is a myth now.")
        return None

    with open(file_path, 'r') as f:
        config = json.load(f)
    return config

def process_binary(file_path):
    if not os.path.exists(file_path):
        print(f"Bruh, {file_path} is ghosting you.")
        return

    print(f"opening the sacred binary file: {file_path}")
    with open(file_path, 'rb') as f:
        data = f.read()
        print(f"Binary Data (hex): {data.hex()}")

def main():
    config_path = 'config.json'
    binary_path = 'bin.txt'

    print("Loading...")
    config = load_config(config_path)
    if config:
        print(f"Config loaded: {config}")
    
    print("\nprocessing binary...")
    process_binary(binary_path)

if __name__ == "__main__":
    main()
