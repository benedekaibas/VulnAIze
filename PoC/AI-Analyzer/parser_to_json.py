import os
import json
from parser import ASTCode, Visitor

def parse_folder(folder_path: str, label: int) -> list:
    results = []

    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".c") or file.endswith(".cpp"):
                full_path = os.path.join(root, file)
                try:
                    # Parse AST and tokenize
                    ast_code = ASTCode(full_path)
                    ast_code.parse_code()

                    if not ast_code.ast:
                        print(f"[!] Skipping (parse failed): {full_path}")
                        continue

                    visitor = Visitor()
                    visitor.visit(ast_code.ast)

                    result = {
                        "filename": file,
                        "label": label,
                        "raw_code": ast_code.raw_code,
                        "tokens": ast_code.tokens,
                        "features": visitor.features,
                        "errors": visitor.errors  # optional
                    }

                    results.append(result)
                except Exception as e:
                    print(f"❌ Error processing {full_path}: {e}")

    return results

if __name__ == "__main__":
    safe_dir = "prototype_dataset/safe"
    vuln_dir = "prototype_dataset/vulnerable"

    print("🔎 Parsing safe files...")
    safe_data = parse_folder(safe_dir, label=0)

    print("🔎 Parsing vulnerable files...")
    vuln_data = parse_folder(vuln_dir, label=1)

    full_data = safe_data + vuln_data

    with open("prototype_data.json", "w") as f:
        json.dump(full_data, f, indent=2)

    print(f"\n✅ Parsed {len(full_data)} files → saved to prototype_data.json")
