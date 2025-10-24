import json
import os
dirName='./cleaned'
filenames=os.listdir(dirName)
with open (dirName+'/clean_merged.jsonl','w') as output_file:
    for name in filenames:
        with open(dirName+'/'+name,'r') as file:
            try:
                for line in file:
                    entry=json.loads(line.strip())
                    code=entry.get("code")
                    vulType=entry.get("vulnerability_type")
                    classification=entry.get("classification")
                    new_entry={
                        "code":code,
                        "vulnerability_type":vulType,
                        "classification":classification
                    }
                    output_file.write(json.dumps(new_entry)+"\n")

            except:
                print(f"{line.strip()} - {name}")