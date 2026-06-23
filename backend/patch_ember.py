path = (
    r"C:\Users\User\AppData\Local\Packages"
    r"\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0"
    r"\LocalCache\local-packages\Python311\site-packages\ember\features.py"
)

with open(path, "r") as f:
    content = f.read()

old = "FeatureHasher(50, input_type=\"string\").transform([raw_obj['entry']]).toarray()[0]"
new = "FeatureHasher(50, input_type=\"string\").transform([[raw_obj['entry']]]).toarray()[0]"

if old in content:
    content = content.replace(old, new)
    with open(path, "w") as f:
        f.write(content)
    print("Patch applied successfully!")
else:
    print("Pattern not found - may already be patched or wording is different")
    # Print line 192 for debugging
    lines = content.splitlines()
    print("Line 192:", lines[191])