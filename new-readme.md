## Project structure


- `dataset` folder
  - `prepared_jsonl` contains all the extract and initially standarized datasets , and `cleaning-code.py` add a final standarization to those dataset and saves the standarized datasets in `standarized` folder.
  - `standarized` folder contains all the standarized datasets.
  - `synthetic` folder contains all the synthetic dataset collected from the LLM and the prompt used to create the synthetic dataset is in readme.md of the folder.
  - `merged_jsonl` contains merged datasets .
  - `deduped` folder contains deduped dataset and the code used to dedupe the dataset such that no duplicates are there in the final dataset.
  - `preprocess` folder contains the code for preprocessing the deduped dataset and the preprocessed dataset `processed_datasetv1.jsonl`.
  - `final-dataset` folder contains the code that turns dataset into a Conversation format and the final dataset used for finetuning.
- `finetuning` folder contains the notebook file used for the final finetuning of the current model. 
- `model-evaluation` folder contains the notebook folder for evalutaing the model performance on real world dataset, datasets from llm .
  - The `testcases-prompt.md` contains the prompt used to get test dataset from LLM.
  - After generating the test dataset list from LLM, paste it in the notebook and asign it a variable . then pass that variable to `evaluate_model` function like evaluate_model(llm_name,test_cases).
- `misc` folder have miscellaneous files.
