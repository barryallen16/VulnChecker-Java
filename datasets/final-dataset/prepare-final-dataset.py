import json

with (
    open("./preprocess/processed_datasetv1.jsonl", "r") as f_in,
    open("./finetuning_dataset_.jsonl", "w") as f_out,
):
    for line in f_in:
        entry = json.loads(line.strip())
        code = entry.get("code")
        vulnerability_type = entry.get("vulnerability_type")
        classification = entry.get("classification")
        jsonl_obj = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a code vulnerability classifier. Analyze the provided Java code and classify it as either 'VULNERABLE' or 'NOT VULNERABLE'. If vulnerable, specify the exact vulnerability type from the dataset. Respond strictly in this format: 'Classification: <VULNERABLE/NOT VULNERABLE>. Vulnerability Type: <type>'. Do not include reasoning.",
                },
                {"role": "user", "content": code},
                {
                    "role": "assistant",
                    "content": f"Classification: {classification}. Vulnerability Type: {vulnerability_type}",
                },
            ]
        }
        f_out.write(json.dumps(jsonl_obj) + "\n")
print(f"finished writing to {f_out}")