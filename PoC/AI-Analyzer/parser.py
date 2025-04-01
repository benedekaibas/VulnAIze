from pycparser import c_parser, c_ast
from typing import Any, List

fn_path = "../vulnerable_code_dataset/buffer_overflow.c"

with open(fn_path, 'r') as file:
    code = file.read()

parser = c_parser.CParser()
ast = parser.parse(text=code, filename=fn_path, debug=False)


def show_ast(node, indent=0):
    indent_str = '  ' * indent
    node_type = type(node).__name__
    print(f"{indent_str}{node_type}: ")

    for n,v in node.children():
        if isinstance(v, list):
            for item in v:
                show_ast(item, indent + 1)
        elif v is not None:
            show_ast(v, indent + 1)

class FindNode(c_ast.NodeVisitor):
    def find_func(self, node):
        print("Function definition found:", node.decl.name)
        self.generic_visit(node)
    
    def find_return(self, node):
        print("Return statement found!")
        self.generic_visit(node)

show_ast(ast)