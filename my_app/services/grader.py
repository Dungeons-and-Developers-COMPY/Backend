import subprocess
import tempfile

def grade_python(code_str, test_cases):
    results = []
    for case in test_cases:
        input_data = case["input"]
        expected = case["expected_output"]
        
        with tempfile.NamedTemporaryFile(mode='w+', suffix=".py", delete=False) as tmp:
            tmp.write(code_str)
            tmp.flush()
            try:
                output = subprocess.check_output(
                    ['python', tmp.name],
                    input=input_data.encode(),
                    timeout=2
                ).decode().strip()
            except subprocess.CalledProcessError as e:
                output = str(e)
        
        results.append(output == expected)
    return all(results)
