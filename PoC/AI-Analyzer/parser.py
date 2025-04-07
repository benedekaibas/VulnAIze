from pycparser import c_parser, c_ast
from typing import Any, List
import re


from pycparser import c_parser, c_ast
import re


class ASTCode:
    def __init__(self, fn_path: str):
        self.fn_path = fn_path
        self.parser = c_parser.CParser()
        self.ast = None

    def preprocess_code(self, code: str) -> str:
        # Remove single-line comments (// ...)
        code = re.sub(r'//.*', '', code)
        # Remove multi-line comments (/* ... */)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # Replace #include directives with stubs
        code = re.sub(r'#include\s+<.*?>', '', code)
        return code

    def parse_code(self):
        with open(self.fn_path, 'r') as file:
            raw_code = file.read()
            code = self.preprocess_code(raw_code)
            self.ast = self.parser.parse(text=code, filename=self.fn_path, debug=False)

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

    class FindNode(c_ast.NodeVisitor):
        def visit_FuncDef(self, node):
            print(f"Function definition found: {node.decl.name}")
            self.generic_visit(node)

        def visit_Return(self, node):
            print("Return statement found!")
            self.generic_visit(node)

class Visitor:
    def __init__(self):
        self.features = {
            "uses_strcpy": 0,
            "uses_strncpy": 0,
            "num_malloc": 0,
            "num_free": 0
        }

    def visit_func_call(self, node):
        if isinstance(node.name, c_ast.ID):
            func_name = node.name.name

        if func_name == "strcpy":
            self.features["uses_strcpy"] = 1

        elif func_name == "strncpy":
            self.features["uses_strncpy"] = 1

        elif func_name == "malloc":
            self.features["num_malloc"] += 1

        elif func_name == "free":
            self.features["num_free"] += 1

        self.generic_visit(node)


if __name__ == "__main__":
    fn_path = "../vulnerable_code_dataset/buffer_overflow.c"
    ast_code = ASTCode(fn_path)
    ast_code.parse_code()

    if ast_code.ast:
        ast_code.show_ast(ast_code.ast)

    visitor = ast_code.FindNode()
    visitor.visit(ast_code.ast)