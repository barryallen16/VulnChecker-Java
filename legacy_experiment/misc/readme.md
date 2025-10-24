Used this prompt to create the `enhanced_dataset.jsonl`
```
my existing test cases are as follows:



and the evaluation result came as 


i need you to create training datasets in the format like following
{"code": "Runtime.getRuntime().exec(new String[]{\"ls\", \"-la\"});", "vulnerability_type": "safe", "classification": "NOT_VULNERABLE"}
{"code": "public void process(HttpServletRequest req) {\n    String input = req.getParameter(\"input\");\n    Runtime.getRuntime().exec(\"echo \" + input);\n}", "vulnerability_type": "Command Injection", "classification": "VULNERABLE"}
{"code": "@GetMapping(\"/user/{id}\")\npublic User getUser(@PathVariable String id) {\n    return jdbc.query(\"SELECT * FROM users WHERE id = \" + id);\n}", "vulnerability_type": "SQL Injection", "classification": "VULNERABLE"}

so that i can finetune the model again to get better accuarcy.

```