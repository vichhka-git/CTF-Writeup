import json
import subprocess
import os
import torch
import transformers.integrations.accelerate

# Monkey-patch check_and_set_device_map to allow meta device context from pretrained
orig_check = transformers.integrations.accelerate.check_and_set_device_map
def patched_check(device_map):
    from transformers.modeling_utils import get_torch_context_manager_or_global_device
    if device_map is None and not transformers.integrations.accelerate.is_deepspeed_zero3_enabled():
        device_in_context = get_torch_context_manager_or_global_device()
        if device_in_context == torch.device('meta'):
            device_in_context = torch.device('cpu')
        device_map = device_in_context
    return orig_check(device_map)

transformers.integrations.accelerate.check_and_set_device_map = patched_check

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

reconstructed = {}
for i, id_ in enumerate(ids):
    print(f"\n================ Inverting {id_} ================")
    print(f"Known document: {docs[i]}")
    emb_tensor = torch.tensor([embs[i]], dtype=torch.float32)
    
    # Invert using exact specs from Gregory's email: num_steps=4, sequence_beam_width=5
    results = vec2text.invert_embeddings(
        embeddings=emb_tensor,
        corrector=corrector,
        num_steps=4,
        sequence_beam_width=5
    )
    print(f"Reconstructed: {results[0]}")
    reconstructed[id_] = results[0]

print("\n================ Reconstructed Summary ================")
for k, v in reconstructed.items():
    print(f"{k}: {v}")

# Try cracking specs.7z with candidate passwords
candidates = [
    reconstructed.get("user_password_requirements", "").strip(),
    reconstructed.get("magic_string", "").strip(),
    reconstructed.get("user_hash_sha256", "").strip(),
]

# Variations
req = reconstructed.get("user_password_requirements", "").strip()
magic = docs[2] if docs[2] else "sunshinectf8_"
candidates.extend([
    req,
    f"{magic}{req}",
    f"{req}{magic}",
    req.lower(),
    req.upper(),
])

print("\nTesting passwords against specs.7z...")
found_pw = None
for pw in candidates:
    if not pw:
        continue
    cmd = ["7z", "x", f"-p{pw}", "-y", "specs.7z"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"SUCCESS with password: {pw}")
        found_pw = pw
        break
    else:
        print(f"Failed with pw: {pw}")

if os.path.exists("flag.txt"):
    with open("flag.txt") as f:
        flag = f.read().strip()
    print(f"\nFLAG: {flag}")
    with open("FLAG.txt", "w") as f:
        f.write(flag)
