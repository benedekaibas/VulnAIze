"""AI model for analyzing C code bases and detect vulnerable code."""

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from collections import Counter
import json
import re

EXPECTED_FEATURES = ["uses_strcpy", "uses_strncpy", "num_malloc", "num_free", "null_assignment_count"]

# Load JSON data
with open("prototype_data.json") as f:
    data = json.load(f)

# Build vocabulary
all_tokens = [t for d in data for t in d["tokens"]]
token_freq = Counter(all_tokens)
vocab = {token: idx + 2 for idx, (token, _) in enumerate(token_freq.items())}
vocab["<PAD>"] = 0
vocab["<UNK>"] = 1

def tokens_to_ids(tokens, vocab, max_len):
    ids = [vocab.get(tok, vocab["<UNK>"]) for tok in tokens]
    ids = ids[:max_len] + [vocab["<PAD>"]] * max(0, max_len - len(ids))
    return ids

class VulnerabilityDataset(Dataset):
    def __init__(self, data, vocab, max_len=100):
        self.vocab = vocab
        self.max_len = max_len
        self.inputs = [tokens_to_ids(d["tokens"], vocab, max_len) for d in data]
        self.features = [
            [d["features"].get(key, 0) for key in EXPECTED_FEATURES]
            for d in data
        ]
        self.labels = [1 if "strcpy" in d["tokens"] or "errors" in d and len(d["errors"]) > 0 else 0 for d in data]

    def __len__(self):
        return len(self.inputs)

    def __getitem__(self, idx):
        token_ids = torch.tensor(self.inputs[idx])
        features = torch.tensor(self.features[idx], dtype=torch.float32)
        label = torch.tensor(self.labels[idx], dtype=torch.float32)
        return token_ids, features, label

class BGRUWithFeatures(nn.Module):
    def __init__(self, vocab_size, feature_dim, embedding_dim=64, hidden_dim=128):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.gru = nn.GRU(embedding_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.feature_fc = nn.Linear(feature_dim, 64)
        self.final_fc = nn.Linear(hidden_dim * 2 + 64, 1)
        self.dropout = nn.Dropout(0.3)
        self.sigmoid = nn.Sigmoid()

    def forward(self, token_ids, static_features):
        x = self.embedding(token_ids)                       # [B, T] → [B, T, D]
        _, h_n = self.gru(x)                                # h_n: [2, B, H]
        h = torch.cat((h_n[0], h_n[1]), dim=1)              # [B, 2H]
        f = torch.relu(self.feature_fc(static_features))    # [B, F] → [B, 64]
        out = torch.cat((h, f), dim=1)                      # [B, 2H+64]
        out = self.dropout(out)
        return self.sigmoid(self.final_fc(out)).squeeze(1)  # [B] logits

def train_model(model, dataloader, epochs=10):
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCELoss()

    model.train()
    for epoch in range(epochs):
        total_loss = 0
        for tokens, feats, labels in dataloader:
            preds = model(tokens, feats)
            loss = criterion(preds, labels)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"Epoch {epoch + 1}/{epochs} - Loss: {total_loss:.4f}")

MAX_LEN = 100
BATCH_SIZE = 32
dataset = VulnerabilityDataset(data, vocab, max_len=MAX_LEN)
dataloader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

feature_dim = len(dataset[0][1])
model = BGRUWithFeatures(vocab_size=len(vocab), feature_dim=feature_dim)

train_model(model, dataloader)


# EVALUATE THE PERFORMANCE OF THE MODEL

def eval_result(model, dataloader):
    """Evaluate the result that comes from the training model"""

    model.eval()
    y_true, y_pred = [], []

    with torch.no_grad():
        for tokens, feats, labels in dataloader:
            preds = model(tokens, feats)
            y_true += labels.tolist()
            y_pred += (preds > 0.5).float.tolist()

    from sklearn.metrics import classification_report, confusion_matrix
    print(classification_report(y_true, y_pred, digits=4))
    print(confusion_matrix(y_true, y_pred))


def flagged_code(model, dataset, threshold=0.75):
    """Print filenames where the model predicts high vulnerability"""
    model.eval()
    with torch.no_grad():
        for i, (tokens, feats, _) in enumerate(dataset):
            pred = model(tokens.unsqueeze(0), feats.unsqueeze(0)).item()
            if pred > threshold:
                print(f"⚠️  Likely vulnerable (score={pred:.2f}) → {data[i]['filename']}")


eval_result(model, dataloader)
flagged_code(model, dataset, threshold=0.75)
