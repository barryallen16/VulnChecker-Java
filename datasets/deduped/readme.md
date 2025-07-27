There could be duplicates in the datasaet as we have combined all the standarized dataset along synthetic dataset , so we dedupe the datset.
- we do this by computing a hash of each line in jsonl file and remove line where a hash collision occurs.
- `dedupe.py` is used to dedupe the dataset.
