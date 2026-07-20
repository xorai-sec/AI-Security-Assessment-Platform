import torch
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL_ID = "inceptionai/jais-13b"

app = FastAPI(title="Jais-13B OpenAI-Compatible Server")

class CompletionRequest(BaseModel):
    model: str | None = "jais-13b"
    prompt: str
    max_tokens: int = 160
    temperature: float = 0.3
    top_p: float = 0.9

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(
    MODEL_ID,
    trust_remote_code=True,
)

print("Loading model. This can take several minutes...")
device = "cuda" if torch.cuda.is_available() else "cpu"
dtype = torch.float16 if device == "cuda" else torch.float32

model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    trust_remote_code=True,
    device_map="auto" if device == "cuda" else None,
    torch_dtype=dtype,
)

if device == "cpu":
    model = model.to("cpu")

model.eval()
print(f"Jais loaded on {device}")

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model": MODEL_ID,
        "device": device,
        "torch_cuda_available": torch.cuda.is_available(),
    }

@app.post("/v1/completions")
def completions(req: CompletionRequest):
    inputs = tokenizer(req.prompt, return_tensors="pt")
    inputs = {k: v.to(model.device) for k, v in inputs.items()}

    input_len = inputs["input_ids"].shape[-1]
    with torch.no_grad():
        output = model.generate(
            **inputs,
            max_new_tokens=req.max_tokens,
            temperature=req.temperature,
            top_p=req.top_p,
            do_sample=True,
            repetition_penalty=1.1,
            pad_token_id=tokenizer.eos_token_id,
        )

    text = tokenizer.decode(output[0][input_len:], skip_special_tokens=True)

    return {
        "id": "jais-local-completion",
        "object": "text_completion",
        "model": "jais-13b",
        "choices": [
            {
                "index": 0,
                "text": text,
                "finish_reason": "stop"
            }
        ]
    }
