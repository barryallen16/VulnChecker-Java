import json
import os

def merge_jsonl_files(input_dir, output_file):
    jsonl_files = [f for f in os.listdir(input_dir) if f.endswith('.jsonl')]
    
    if not jsonl_files:
        print(f"No .jsonl files found in directory: {input_dir}")
        return
    
    print(f"Merging {len(jsonl_files)} .jsonl files into {output_file}")
    
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for filename in jsonl_files:
            filepath = os.path.join(input_dir, filename)
            print(f"Processing {filename}...")
            
            with open(filepath, 'r', encoding='utf-8') as infile:
                for line in infile:
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                    try:
                        # Parse and re-serialize to ensure clean JSON
                        parsed = json.loads(line)
                        outfile.write(json.dumps(parsed) + '\n')
                    except json.JSONDecodeError as e:
                        print(f"Invalid JSON in {filename}, line skipped: {e}")
                        print(f"Problematic line: {line[:100]}...")  # Print first 100 chars of bad line

    print("Merge completed successfully!")

if __name__ == "__main__":
    input_directory = "./synthetic"  
    output_file_path = "./merged_output_v4.jsonl"    
    merge_jsonl_files(input_directory, output_file_path)