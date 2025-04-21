import re
from pycparser import c_parser, c_ast
from typing import Any, List

def sanitize_code(code: str) -> str:
    # Remove preprocessor lines
    code = re.sub(r'^\s*#.*$', '', code, flags=re.MULTILINE)
    
    # Remove comments
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*', '', code)

    # Remove GCC attributes and declspecs
    code = re.sub(r'__attribute__\s*\(\(.*?\)\)', '', code)
    code = re.sub(r'__declspec\s*\(.*?\)', '', code)

    # Replace wchar_t and other unknown types
    code = re.sub(r'\bwchar_t\b', 'char', code)
    code = re.sub(r'\bint64_t\b', 'int', code)
    code = re.sub(r'\bsize_t\b', 'int', code)
    code = re.sub(r'\buint64_t\b', 'unsigned int', code)

    # Remove inline function definitions with function pointers
    code = re.sub(r'\w+\s*\(\s*\*\s*\w+\s*\)\s*\([^)]*\)', 'int', code)

    # Strip invalid struct members with * or complicated types
    code = re.sub(r'struct\s+\w+\s*{[^}]*};', '', code, flags=re.DOTALL)

    return code

class ASTCode:
    def __init__(self, fn_path: str):
        self.fn_path = fn_path
        self.parser = c_parser.CParser()
        self.ast = None
        self.raw_code = ""
        self.tokens = []

    def preprocess_code(self, code: str) -> str:
        return sanitize_code(code)

    def parse_code(self):
        with open(self.fn_path, 'r') as file:
            raw = file.read()
            self.raw_code = raw
            clean_code = self.preprocess_code(raw)
            self.ast = self.parser.parse(text=clean_code, filename=self.fn_path, debug=False)
            self.tokenize_code()

    def tokenize_code(self):
        if self.raw_code:
            self.tokens = re.findall(r'\w+|[^\s\w]', self.raw_code)

    def show_ast(self, node, indent=0):
        indent_str = '  ' * indent
        node_type = type(node).__name__
        print(f"{indent_str}{node_type}: ")
        for n, v in node.children():
            if isinstance(v, list):
                for item in v:
                    self.show_ast(item, indent + 1)
            elif v is not None:
                self.show_ast(v, indent + 1)

class Visitor(c_ast.NodeVisitor):
    def __init__(self):
        self.features = {
            "uses_strcpy": 0,
            "uses_strncpy": 0,
            "num_malloc": 0,
            "num_free": 0
        }
        self.scopes = [{}]
        self.errors = []

    def visit_FuncCall(self, node):
        func_name = node.name.name if isinstance(node.name, c_ast.ID) else None
        if func_name == "strcpy":
            self.features["uses_strcpy"] = 1
        elif func_name == "strncpy":
            self.features["uses_strncpy"] = 1
        elif func_name == "malloc":
            self.features["num_malloc"] += 1
        elif func_name == "free":
            self.features["num_free"] += 1
        self.generic_visit(node)

    def visit_Assignment(self, node):
        if isinstance(node.rvalue, c_ast.ID) and node.rvalue.name == "NULL":
            var_name = node.lvalue.name if isinstance(node.lvalue, c_ast.ID) else None
            if var_name:
                self.scopes[-1][var_name] = {'initialized': False}
        else:
            if isinstance(node.lvalue, c_ast.ID):
                var_name = node.lvalue.name
                if var_name not in self.scopes[-1]:
                    self.scopes[-1][var_name] = {}
                self.scopes[-1][var_name]['initialized'] = True
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if node.op == '*' and isinstance(node.expr, c_ast.ID):
            var_name = node.expr.name
            var_info = self.scopes[-1].get(var_name, {})
            if var_info.get('initialized') is False:
                self.features["null_assignment_count"] = self.features.get("null_assignment_count", 0) + 1
                self.errors.append(f"Potential null pointer dereference at line {node.coord.line}: '{var_name}' might be NULL")
        self.visit(node.expr)

    def visit_FuncDef(self, node):
        self.scopes.append({})
        if node.decl.type.args:
            for param in node.decl.type.args.params:
                self.visit(param)
        self.visit(node.body)
        self.scopes.pop()

def analyze_file(fn_path: str):
    ast_code = ASTCode(fn_path)
    try:
        ast_code.parse_code()
    except Exception as e:
        print(f"❌ Error processing {fn_path}: {e}")
        return None

    visitor = Visitor()
    visitor.visit(ast_code.ast)

    return {
        "filename": fn_path,
        "raw_code": ast_code.raw_code,
        "tokens": ast_code.tokens,
        "features": visitor.features,
        "null_assignment_count": visitor.features.get("null_assignment_count", 0),
        "num_errors": len(visitor.errors),
        "errors": visitor.errors
    }

if __name__ == "__main__":
    result = analyze_file("example.c")
    print(result)
