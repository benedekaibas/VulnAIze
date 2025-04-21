import os 
import shutil

SRC_DIR = "dataset"
DESTINATION_DIR = "proto_dataset"
NUM_FILES_PER_CWE = 40

# make the destination folder for storing data
if not os.path.exists(DESTINATION_DIR):
    os.makedirs(DESTINATION_DIR)

def copy_example(cwe_folder):
    good_code = []
    vulnerable_code = []

    for root, _, files in os.walk(cwe_folder):
        for file in files:
            full_path = os.path.join(root, file)
            if "good" in file.lower():
                good_code.append(full_path)
            elif "bad" in file.lower():
                vulnerable_code.append(full_path)
    
    good_code = good_code[:NUM_FILES_PER_CWE // 2]
    vulnerable_code = vulnerable_code[:NUM_FILES_PER_CWE // 2]

    for src_file in good_code + vulnerable_code:
        label = "safe" if "good" in src_file else "vulnerable"
        target_dir = os.path.join(DESTINATION_DIR, label)
        os.makedirs(target_dir, exist_ok=True)
        shutil.copy(src_file, os.path.join(target_dir, os.path.basename(src_file)))
    
    for cwe in os.listdir(SRC_DIR):
        full_cwe_path = os.path.join(SRC_DIR, cwe)
        if os.path.isdir(full_cwe_path):
            print(f"Processing: {cwe}")
            copy_example(full_cwe_path)

print("Dataset created in the dataset folder!")