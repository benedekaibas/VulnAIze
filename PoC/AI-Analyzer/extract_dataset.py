import os
import shutil

SRC_DIR = "/home/benedek-kaibas/Documents/VulnAIze/PoC/dataset"
DEST_DIR = "prototype_dataset"
N_FILES_PER_CWE = 20  # 10 good, 10 bad

if not os.path.exists(DEST_DIR):
    os.makedirs(DEST_DIR)

def copy_examples(cwe_folder):
    good_files = []
    bad_files = []

    for root, _, files in os.walk(cwe_folder):
        for file in files:
            if file.endswith(".c"):
                full_path = os.path.join(root, file)
                if "good" in file.lower():
                    good_files.append(full_path)
                elif "bad" in file.lower():
                    bad_files.append(full_path)

    # Keep only N files per label
    good_files = good_files[:N_FILES_PER_CWE // 2]
    bad_files = bad_files[:N_FILES_PER_CWE // 2]

    for src_file in good_files + bad_files:
        label = "safe" if "good" in src_file else "vulnerable"
        target_dir = os.path.join(DEST_DIR, label)
        os.makedirs(target_dir, exist_ok=True)
        shutil.copy(src_file, os.path.join(target_dir, os.path.basename(src_file)))

# Run on all CWE folders
for cwe in os.listdir(SRC_DIR):
    full_cwe_path = os.path.join(SRC_DIR, cwe)
    if os.path.isdir(full_cwe_path):
        print(f"Processing: {cwe}")
        copy_examples(full_cwe_path)

print("✅ Mini dataset created in 'prototype_dataset/'")
