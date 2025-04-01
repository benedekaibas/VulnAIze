from pycparser import c_parser, c_ast
from typing import Any, List

fn_path = "../vulnerable_code_dataset/buffer_overflow.c"

with open(fn_path, 'r') as file:
    code = file.read()

parser = c_parser.CParser()
ast = parser.parse(text=code, filename=code, debug=False)


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

show_ast(ast)