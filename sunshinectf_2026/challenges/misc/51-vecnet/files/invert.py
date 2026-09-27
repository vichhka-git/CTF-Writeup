import json
import torch
import vec2text

print("Loading embeddings...")
with open("chroma_embeddings.json") as f:
    data = json.load(f)

ids = data["ids"]
embs = data["embeddings"]
docs = data["documents"]

device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Using device: {device}")

print("Loading corrector for gtr-base...")
corrector = vec2text.load_pretrained_corrector("gtr-base")

for i, id_ in enumerate(ids):
    print(f"\n================ Inverting {id_} ================")
    print(f"Known document: {docs[i]}")
    emb_tensor = torch.tensor([embs[i]], dtype=torch.float32)
    
    # Invert using exact specs from email: num_steps=4, sequence_beam_width=5
    results = vec2text.invert_embeddings(
        embeddings=emb_tensor,
        corrector=corrector,
        num_steps=4,
        sequence_beam_width=5
    )
    print(f"Reconstructed text: {results[0]}")
