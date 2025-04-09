import os
from parser import ASTCode
from parser import Visitor

ast = ASTCode()
visitor = Visitor()
parser = ASTCode.parse_code()

results = []
dataset = "../vulnerable_code_dataset"

for fn in os.listdir(dataset):
    if fn.endswith('.c'):
        file_path = os.path.join(dataset, fn)
        ast(file_path).parser

        if not ast.ast:
            continue
        
        visitor.visit(ast.ast)

        result = visitor.features.copy()
        result = visitor.features.copy()
        result["filename"] = fn
        result["null_assignment_count"] = result.get("null_assignment_count", 0)
        result["num_errors"] = len(visitor.errors)
        results.append(result)
