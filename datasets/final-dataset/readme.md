`prepare-final-dataset.py` is used to turn all the merged dataset into a Conversation format that will be used for the finetuning of the model.
--- 
`previous-versions` folder contains the previous versions that we used to finetune the model.

the `finetuning_dataset.jsonl` is the dataset that is going to be used for finetuning.

```
The dataset has
NOT_VULNERABLE    34517
VULNERABLE        33054
```

the `finetuning_datasetv2.jsonl` is the dataset that is going to be used for finetuning.
```
The dataset has
classification
NOT_VULNERABLE    34703
VULNERABLE        33289
```
so they both can be considered as a balanced dataset.
---
The `finetuning_dataset_v3.jsonl` is used to finetune the current best model.
it is a balanced dataset having 
```
classification	
VULNERABLE	36232
NOT_VULNERABLE	35533
```