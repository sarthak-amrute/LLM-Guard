from fastapi import FastAPI, HTTPException
from google import genai
from google.genai import types
from pydantic import BaseModel

from app.config import GEMINI_API_KEY, DEFAULT_MODEL, FALLBACK_MODELS, TARGET_MODE
from app.prompt import SECURE_SYSTEM_PROMPT, VULNERABLE_SYSTEM_PROMPT

from app.retriever import retrieve_knowledge
from app.knowledge import load_knowledge
from app.protected_data import load_protected_data


app = FastAPI(
    title="TechMart Customer Support API",
    version="1.0.0"
)


client = genai.Client(api_key=GEMINI_API_KEY)
knowledge = load_knowledge()
protected_data = load_protected_data()
current_mode = TARGET_MODE if TARGET_MODE in ("SECURE", "VULNERABLE") else "SECURE"


class ChatRequest(BaseModel):
    message: str


class ModeRequest(BaseModel):
    mode: str


@app.get("/")
def root():
    return {
        "message": "TechMart Customer Support API is Running",
        "mode": current_mode
    }


@app.get("/mode")
def get_mode():
    return {
        "mode": current_mode
    }


@app.post("/mode")
def set_mode(request: ModeRequest):
    global current_mode
    mode_upper = request.mode.strip().upper()
    if mode_upper not in ("SECURE", "VULNERABLE"):
        raise HTTPException(
            status_code=400,
            detail="Invalid mode. Supported modes are 'SECURE' and 'VULNERABLE'."
        )
    current_mode = mode_upper
    return {
        "mode": current_mode,
        "message": f"Target mode switched to {current_mode}"
    }


@app.post("/chat")
def chat(request: ChatRequest):

    relevant_knowledge = retrieve_knowledge(
        request.message,
        knowledge
    )

    if current_mode == "VULNERABLE":
        system_instruction = VULNERABLE_SYSTEM_PROMPT
    else:
        system_instruction = SECURE_SYSTEM_PROMPT

    prompt = f"""
Relevant TechMart information:

{relevant_knowledge}

Internal protected information:

{protected_data}

Customer question:

{request.message}
"""

    models_to_try = [DEFAULT_MODEL] + [m for m in FALLBACK_MODELS if m != DEFAULT_MODEL]
    last_error = None
    response_text = None

    gen_config = types.GenerateContentConfig(
        system_instruction=system_instruction,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True)
    )


    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=gen_config
            )
            if response:
                text = getattr(response, "text", None)
                if not text and hasattr(response, "candidates") and response.candidates:
                    first_cand = response.candidates[0]
                    if hasattr(first_cand, "content") and first_cand.content and first_cand.content.parts:
                        text = first_cand.content.parts[0].text
                if text:
                    response_text = text
                    break
        except Exception as e:
            last_error = e
            continue

    if response_text is None:
        raise HTTPException(
            status_code=502,
            detail=f"All upstream Gemini model calls failed. Last error: {last_error}"
        )

    return {
        "response": response_text
    }
