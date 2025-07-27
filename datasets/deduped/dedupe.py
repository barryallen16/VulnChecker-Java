import json
import hashlib

def dedup_jsonl_by_hash(input_file, output_file):
    seen_hashes = set()
    unique_lines = 0
    total_lines = 0

    try:
        with open(input_file, "r", encoding="utf-8") as infile,open(output_file, "w", encoding="utf-8") as outfile:
            for line in infile:
                total_lines += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    json.loads(line)
                    line_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
                    if line_hash not in seen_hashes:
                        seen_hashes.add(line_hash)
                        outfile.write(line + "\n")
                        unique_lines += 1
                    else:
                        print(f"Duplicate hash found, skipping line: {line[:50]}...")

                except json.JSONDecodeError as e:
                    print(f"Warning: Skipping invalid JSON line: {line[:50]}... ({e})")
                except Exception as e:
                    print(f"Error processing line: {line[:50]}... ({e})")

        print(f"Processed {total_lines} lines, kept {unique_lines} unique lines")
        print(f"Output written to {output_file}")

    except FileNotFoundError:
        print(f"Error: Input file {input_file} not found")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    input_jsonl = "./cleaned/final-dataset/clean+enhanced.jsonl"
    output_jsonl = "./cleaned/final-dataset/deduped_clean_enhance.jsonl"
    dedup_jsonl_by_hash(input_jsonl, output_jsonl)
