import os
import json
from parser import ASTCode, Visitor

results = []
dataset_path = "../vulnerable_code_dataset"

for fn in os.listdir(dataset_path):
    if fn.endswith('.c'):
        file_path = os.path.join(dataset_path, fn)

        # Parse the file and tokenize
        ast_code = ASTCode(file_path)
        ast_code.parse_code()

        if not ast_code.ast:
            print(f"[!] Skipping {fn} (could not parse)")
            continue

        # Visit and analyze
        visitor = Visitor()
        visitor.visit(ast_code.ast)

        # Dictionary for storing result records
        result = {
            "filename": fn,
            "raw_code": ast_code.raw_code,
            "tokens": ast_code.tokens,
            "features": visitor.features,
            "null_assignment_count": visitor.features.get("null_assignment_count", 0),
            "num_errors": len(visitor.errors),
            "errors": visitor.errors
        }

        results.append(result)

# Export to JSON and then print result
with open("vulnerability_results.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\n✅ Exported {len(results)} files to vulnerability_results.json")
