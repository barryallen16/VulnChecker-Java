`preprocess` folder contains :
- `java-preprocessing-notebook.ipynb` , notebook used to preprocess the standardized code and engineer features. 
    - preprocess process includes :
        - cleaning : remove unnecessary whitespaces
        - parsing : parse code to extract class/method signatures, control structures, and sensitive APIs
        - segmentation : breaking the code into managable small chunks such that model can focus on all parts of the code and just well within the models context length.
        - data flow analysis : determine taint sources and sinks 
    - feature engineering include adding metadata to the code such as human hints, this helps the model to get smarter at analysing the code.
- `processed_datasetv1.jsonl` , dataset after running the `java-preprocessing-notebook.ipynb` notebook