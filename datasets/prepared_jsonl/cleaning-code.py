import json
import os

dir_files = os.listdir()
files = [file_name for file_name in dir_files if file_name.endswith(".jsonl")]
for file_name in files:
    with (
        open(f"./prepared_jsonl/{file_name}", "r") as file,
        open(f"./cleaned/{file_name}", "w") as output_file,
    ):
        for line in file:
            entry = json.loads(line.strip())
            code: str = entry.get("code")
            if code.startswith("```java\n"):
                vulType = entry.get("label")
                if vulType == "safe":
                    classification = "NOT_VULNERABLE"
                else:
                    classification = "VULNERABLE"
                new_entry = {
                    "code": code,
                    "vulnerability_type": vulType,
                    "classification": classification,
                }
                output_file.write(json.dumps(new_entry) + "\n")
        print(
            f"finished standarizing ./prepared_jsonl/{file_name} into ./cleaned/{file_name}"
        )
