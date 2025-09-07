"""
Ollama Prompt Wrapper
---------------------
Utility for safely invoking a local Ollama LLM (default: llama3.1) with retry 
logic, memory error handling, and user prompts to free resources if needed. 
Designed for SOC automation workflows where MITRE ATT&CK mapping or enrichment 
requires structured JSON responses from a local model.
"""


#!/usr/bin/env python3
import os
import time
import ollama
import fire  # pip install fire
import beep

# Force the client to talk only to localhost
os.environ["OLLAMA_HOST"] = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

def _looks_like_memory_error(err_msg: str) -> bool:
    msg = err_msg.lower()
    return any(
        k in msg
        for k in [
            "out of memory",
            "cuda error",
            "mmap",           # memory mapping failures
            "resource temporarily unavailable",
            "cannot allocate memory",
            "std::bad_alloc",
        ]
    )

def run_ollama(prompt: str, ollama_model: str = "llama3.1:latest", max_retries: int = 3) -> str:
    """
    Call Ollama safely. If a failure occurs (esp. memory/OOM), prompt the user to
    close apps to free memory and press Enter to retry. Returns "" on final failure.
    """

    attempt = 1
    while attempt <= max_retries:
        try:
            print(f"\n[Prompting Ollama local LLM: {ollama_model}]\n")
            resp = ollama.chat(
                model=ollama_model,
                messages=[{"role": "user", "content": prompt}],
                stream=False,
                options={
                    # Guardrails: low-variance decoding & short outputs
                    "temperature": 0.1,
                    "top_p": 0.9,
                    "num_predict": 200,
                    "num_ctx": 4096,  # reduce to 2048 if you hit OOM
                    "num_thread": os.cpu_count() or 4,
                },
                format="json"  # asks Ollama to produce JSON
            )
            return resp["message"]["content"]
        except Exception as e:
            err = str(e)
            print(f"[WARN] Ollama call failed (attempt {attempt}/{max_retries}): {err}")

            # If it's likely a memory issue, ask the user to free memory and retry
            if _looks_like_memory_error(err) or "status code: 500" in err.lower():
                beep.beep()     # Send a notification sound for user attention
                print(
                    "\nIt looks like the model may have run out of memory or crashed.\n"
                    "👉 Please close any unused applications/windows to free RAM/VRAM,\n"
                    "   then press Enter to try again (or type 's' to skip): ",
                    end="",
                )
                choice = input().strip().lower()
                if choice == "s":
                    print("[INFO] Skipping LLM call at user request.")
                    return "s"
                # user pressed Enter → retry same attempt number incremented below
            else:
                # Non-memory error: brief delay then retry
                time.sleep(1.5)

            attempt += 1

    print("[ERROR] LLM call failed after retries; continuing without LLM output.")
    return ""

if __name__ == "__main__":
    fire.Fire(run_ollama)
