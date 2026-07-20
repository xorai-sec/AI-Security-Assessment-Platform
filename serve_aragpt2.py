import torch
import uuid
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL_ID = "aubmindlab/aragpt2-mega"

app = FastAPI(title="AraGPT2 Arabic Base Model Server")

class CompletionRequest(BaseModel):
    model: str | None = "aragpt2-mega"
    prompt: str
    max_tokens: int = 120
    temperature: float = 0.7
    top_p: float = 0.9

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, trust_remote_code=True)

print("Loading model...")
device = "cuda" if torch.cuda.is_available() else "cpu"
dtype = torch.float16 if device == "cuda" else torch.float32

model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    torch_dtype=dtype,
    trust_remote_code=True,
)

model = model.to(device)

# Compatibility patch for AraGPT2 custom model code with older transformers.
# The custom model calls this helper, but transformers 4.28 does not expose it.
if hasattr(model, "transformer") and not hasattr(model.transformer, "warn_if_padding_and_no_attention_mask"):
    def _warn_if_padding_and_no_attention_mask(input_ids, attention_mask=None):
        return None
    model.transformer.warn_if_padding_and_no_attention_mask = _warn_if_padding_and_no_attention_mask

model.eval()

print(f"AraGPT2 loaded on {device}")

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model": MODEL_ID,
        "served_model": "aragpt2-mega",
        "device": device,
        "torch_cuda_available": torch.cuda.is_available(),
    }

@app.post("/v1/completions")
def completions(req: CompletionRequest):
    inputs = tokenizer(req.prompt, return_tensors="pt")
    inputs = {k: v.to(device) for k, v in inputs.items()}
    input_len = inputs["input_ids"].shape[-1]

    with torch.no_grad():
        output = model.generate(
            **inputs,
            max_new_tokens=req.max_tokens,
            temperature=req.temperature,
            top_p=req.top_p,
            do_sample=True,
            repetition_penalty=1.08,
            pad_token_id=tokenizer.eos_token_id,
        )

    text = tokenizer.decode(output[0][input_len:], skip_special_tokens=True)

    return {
        # A unique ID lets every framework correlate the exact response with
        # its request; a constant ID makes independent generations look mixed
        # in traffic logs and reports.
        "id": f"aragpt2-completion-{uuid.uuid4().hex}",
        "object": "text_completion",
        "model": "aragpt2-mega",
        "choices": [
            {
                "index": 0,
                "text": text,
                "finish_reason": "stop"
            }
        ]
    }
