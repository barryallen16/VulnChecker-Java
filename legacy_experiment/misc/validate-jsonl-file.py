import json

file_path = "./cleaned/to_join.jsonl"

with open(file_path, 'r') as f:
    for i, line in enumerate(f):
        try:
            json.loads(line)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON on line {i+1}: {e}")
            print(f"Problematic line: {line.strip()}")
            break 