from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from models import ScanRequest, ScanResult
from dotenv import load_dotenv
from analyzer import analyze

load_dotenv()

app = FastAPI(title = "Net scanner")

app.add_middleware(CORSMiddleware,
                   allow_origins = ["http://localhost:5173"],
                   allow_methods = ["POST", "GET"],
                   allow_headers = ["Content-Type"])

@app.get("/")
def origin():

    return {"message": "Welcome"}

@app.get("/health")
def health():

    return {"status": "OK"}

@app.post("/scan", response_model = ScanResult)
async def analyze_request(request: ScanRequest):

    return await analyze(request)
