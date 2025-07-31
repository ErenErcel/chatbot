import requests

class LLMClient:
    def __init__(self, model="llama3"):
        self.base_url = "http://localhost:11434/api/generate"
        self.model = model

    def generate(self, prompt):
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }

        try:
            response = requests.post(self.base_url, json=payload)
            response.raise_for_status()
            return response.json()["response"]
        except Exception as e:
            print(f"LLM hatası: {e}")
            return "Üzgünüm, şu anda bir teknik sorun yaşıyoruz."