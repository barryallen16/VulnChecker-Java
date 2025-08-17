## TO create the testcases using llm use the below prompt .
```
i have finetuned a model that can classify java code as vulnerable or not_vulnerable.
i need you to create a testing dataset in the following format so that i can evaluate the model.
[{
        "code": 'public class Example8 {\n    public static void main(String[] args) {\n        String password = "secret";\n        System.out.println(password);\n    }\n}',
        "expected": "VULNERABLE",
    },
    {
        "code": 'public class Example17 {\n    public static void main(String[] args) throws Exception {\n        String fileName = args[0];\n        if (!fileName.matches("[a-zA-Z0-9]+\\\\.txt")) {\n            throw new IllegalArgumentException("Invalid file name");\n        }\n        File file = new File("uploads/" + fileName);\n        FileInputStream fis = new FileInputStream(file);\n    }\n}',
        "expected": "NOT_VULNERABLE",
    }]
```

---

After generating the test dataset list from LLM, paste it in the notebook and asign it a variable . then pass that variable to `evaluate_model` function like evaluate_model(llm_name,test_cases).