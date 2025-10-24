## Project structure

- `dataset` folder
  - `prepared_jsonl` holds the extracted and initially standardised datasets. `cleaning-code.py` adds a final standardisation and saves the result in `standarized`.
  - `standarized` holds all the standardised datasets.
  - `synthetic` holds the synthetic datasets collected from the LLM. The prompt used to create them is in `readme.md` inside that folder.
  - `merged_jsonl` holds merged datasets.
  - `deduped` holds the deduplicated dataset and the code used to remove duplicates.
  - `preprocess` holds the preprocessing code and the preprocessed dataset `processed_datasetv1.jsonl`.
  - `final-dataset` holds the code that converts the dataset into conversation format and the final dataset used for finetuning.
- `finetuning` holds the notebook used for the final finetuning of the current model.
- `model-evaluation` holds the notebooks used to evaluate the model on real-world datasets and LLM datasets.
  - `testcases-prompt.md` is the prompt used to generate the test dataset from the LLM. After generating the list, paste it into the notebook, assign it to a variable, and pass that variable to `evaluate_model` like `evaluate_model(llm_name, test_cases)`.
- `misc` holds miscellaneous files.
