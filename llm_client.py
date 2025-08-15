# Bu modül, yerel LLM API ile iletişimi yönetir.
import requests

# LLMClient sınıfı, yerel LLM sunucusuna yapılan istekleri yönetir.
class LLMClient:
    # Bağlantı parametrelerini başlatır.
    def __init__(self, model="gemma3:4b"):
        self.base_url = "http://localhost:11434/api/generate"
        self.model = model

    # LLM API'ye bir prompt gönderir ve sonucu döner.
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

# LLM'ye hızlıca sorgu yapmak için yardımcı fonksiyon.
def query_llm(prompt):
    client = LLMClient()
    return client.generate(prompt)