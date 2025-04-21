import os
import shutil

# --- Configuration ---
SRC_DIR = "/home/benedek-kaibas/Documents/VulnAIze/PoC/dataset"
DEST_DIR = "prototype_dataset"
N_FILES_PER_CWE = 20  # total: 10 safe + 10 vulnerable

# Check if the directory storing safe and vulnerable code snippets (dest_dir) already exists. If not it needs to be created
os.makedirs(DEST_DIR, exist_ok=True)

def is_safe(content: str) -> bool:
    """Check for safe codes based on the description in each file."""
    return "goodsink" in content or "goodsource" in content or "good sink" in content or "good source" in content

def is_vulnerable(content: str) -> bool:
    """Check for vulnerable codes based on the description in each file."""
    return (
        "badsink" in content
        or "badsource" in content
        or "bad sink" in content
        or "bad source" in content
    )

def copy_examples(cwe_folder):
    good_files = []
    bad_files = []

    for root, _, files in os.walk(cwe_folder):
        for file in files:
            if file.endswith(".c") or file.endswith(".cpp"):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(2048).lower()  # Read more of the file
                        if is_vulnerable(content):
                            bad_files.append(full_path)
                        elif is_safe(content):
                            good_files.append(full_path)
                except Exception as e:
                    print(f"❌ Error reading {full_path}: {e}")

    print(f"  🟢 Safe: {len(good_files)}, 🔴 Vulnerable: {len(bad_files)}")

    # Trim each list
    good_files = good_files[:N_FILES_PER_CWE // 2]
    bad_files = bad_files[:N_FILES_PER_CWE // 2]

    for src_file in good_files + bad_files:
        label = "safe" if src_file in good_files else "vulnerable"
        target_dir = os.path.join(DEST_DIR, label)
        os.makedirs(target_dir, exist_ok=True)

        dest_path = os.path.join(target_dir, os.path.basename(src_file))
        print(f"📤 Copying {src_file} → {dest_path}")
        shutil.copy(src_file, dest_path)

# --- Run over each CWE folder ---
for cwe_folder in os.listdir(SRC_DIR):
    full_path = os.path.join(SRC_DIR, cwe_folder)
    if os.path.isdir(full_path):
        print(f"\n🔎 Processing: {cwe_folder}")
        copy_examples(full_path)

print("\n✅ Mini dataset created in 'prototype_dataset/'")
