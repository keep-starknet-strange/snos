import json
with open("build/os_latest.json", "r") as f:
    a = json.load(f)
with open("starkware/starknet/security/whitelists/latest.json", "r") as f:
    b = json.load(f)
whitelisted = ["\n".join(hint["hint_lines"]) for hint in b["allowed_reference_expressions_for_hint"]]

hints = []
for i, (k, v) in enumerate(a["hints"].items()):
    for hint in v:
        if hint["code"] not in whitelisted:
            hints.append(hint["code"])
print(hints.index("vm_enter_scope({'syscall_handler': deprecated_syscall_handler})"))