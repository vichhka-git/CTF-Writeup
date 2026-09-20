# Solvers for A1-A4: P-0 AI Agent Challenge Series
# A1: First contact (prompt extraction)
# A2: Indirect injection (mail triage) -> flag{f0rw4rd3d_f4e8e3bff9}
# A3: Template injection (forge a turn)
# A4: Tool abuse (confused deputy) -> flag{sc0p3_byp4ss_c9107ef7aa}

flags = {
    "A2": "flag{f0rw4rd3d_f4e8e3bff9}",
    "A4": "flag{sc0p3_byp4ss_c9107ef7aa}"
}

print("[+] Recovered flags for A1-A4:")
for task, f in flags.items():
    print(f"  {task}: {f}")
