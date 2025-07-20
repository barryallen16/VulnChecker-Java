This folder contains all the synthetic dataset from various llm merged . 
- There are 4 versions as we kept generating more synthetic dataset till we were satisfied . The `merged_output_v4.jsonl` is the final comprehensive synthetic dataset used.
- `merge_synthetic.py` used to merge synthetic datasets from `synthetic` folder into `merged_output_v4.jsonl`. this is the same code (modified a little bit) used to merge all the standarized datasets and the synthetic datasets into `clean_merged.jsonl`
- `clean_merged.jsonl` contains all datasets merged record .
- `enhanced_dataset.jsonl` contains synthetic dataset created after seeing the performance of the finetuned on the real-world cases. it accounts for the vulnerability types the model misclassified.
- `clean+enhanced.jsonl` is the merged dataset of both `clean_merged.jsonl` and `enhanced_dataset.jsonl`
