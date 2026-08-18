import os
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from uvicorn import run as app_run

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.url_analysis.classifier import get_model_and_metadata, predict_with_model
from networksecurity.url_analysis.risk_engine import assess_risk
from networksecurity.url_analysis.validator import URLValidationError, normalize_url
from networksecurity.utils.main_utils.utils import load_object

app = FastAPI(title="Network Security - Website Security Analyzer API", version="2.0.0")

# Local development origins only. Configure additional trusted origins for deployment.
origins = ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="./templates")


class URLAnalysisRequest(BaseModel):
    url: str


@app.post("/api/analyze-url")
async def analyze_url(payload: URLAnalysisRequest):
    """Analyze URL text only; this endpoint never fetches or requests the submitted URL."""
    try:
        normalized_url = normalize_url(payload.url)
    except URLValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    try:
        risk = assess_risk(normalized_url)
        model_result = predict_with_model(normalized_url)
    except Exception as error:
        logging.exception("URL analysis failed")
        raise HTTPException(status_code=500, detail="Unable to analyze this URL.") from error

    security_status = model_result["security_status"] if model_result else risk["prediction"]
    prediction_class = model_result["prediction"] if model_result else risk["prediction"].lower()

    response = {
        "url": normalized_url,
        "prediction": prediction_class,
        "security_status": security_status,
        "threat_type": model_result.get("threat_type") if model_result else prediction_class.capitalize(),
        "confidence": model_result.get("confidence") if model_result else None,
        "probabilities": model_result.get("probabilities") if model_result else None,
        "malicious_probability": model_result.get("malicious_probability") if model_result else None,
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "indicators": risk["indicators"],
        "features": risk["features"],
        "analysis_type": "Trained ML classifier + URL-structure risk indicators" if model_result else "URL-structure heuristic",
        "model_used": bool(model_result),
        "model_name": model_result.get("model_name") if model_result else None,
        "notice": "Risk score and prediction are derived purely from URL structure and machine learning; they are not an absolute guarantee of website safety.",
    }
    return response


@app.get("/api/model-info")
async def get_model_info():
    """Retrieve metadata and evaluation metrics for the trained URL classifier."""
    _, metadata = get_model_and_metadata()
    if not metadata:
        raise HTTPException(status_code=404, detail="No trained URL model metadata found.")
    return metadata


@app.get("/", tags=["authentication"])
async def index():
    return RedirectResponse(url="/docs")


@app.get("/train")
async def train_route():
    try:
        from networksecurity.pipeline.training_pipeline import TrainingPipeline
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e, sys)


def process_prediction(file: UploadFile):
    from networksecurity.utils.ml_utils.model.estimator import NetworkModel
    df = pd.read_csv(file.file)
    preprocessor = load_object("final_model/preprocessor.pkl")
    final_model = load_object("final_model/model.pkl")
    network_model = NetworkModel(preprocessor=preprocessor, model=final_model)
    y_pred = network_model.predict(df)
    return df, y_pred


@app.post("/predict")
async def predict_route(request: Request, file: UploadFile = File(...)):
    try:
        df, y_pred = process_prediction(file)
        df['predicted_column'] = y_pred
        df.to_csv('prediction_output/output.csv')
        table_html = df.to_html(classes='table table-striped')
        return templates.TemplateResponse(request=request, name="table.html", context={"table": table_html})
    except Exception as e:
        raise NetworkSecurityException(e, sys)


@app.post("/api/predict")
async def api_predict_route(request: Request, file: UploadFile = File(...)):
    try:
        df, y_pred = process_prediction(file)
        return {"predictions": y_pred.tolist()}
    except Exception as e:
        raise NetworkSecurityException(e, sys)


if __name__ == "__main__":
    app_run(app, host="0.0.0.0", port=8000)
