import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
import httpx

router = APIRouter()

# Setup audit logger for CJIS tracking
logger = logging.getLogger("sentinel.middleware")

# ==========================================
# 1. NIEM-COMPLIANT PYDANTIC SCHEMA BLOCK
# ==========================================

class IncidentModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True) # V2 Syntax
    
    activity_date: Optional[str] = Field(default=None, alias="nc:ActivityEventDate")
    description: str = Field(alias="nc:ActivityDescriptionText")

    class Config:
        populate_by_name = True  # Allows parsing raw dict inputs using aliases

class PersonModel(BaseModel):
    given_name: Optional[str] = Field(default=None, alias="nc:PersonGivenName")
    surname: str = Field(alias="nc:PersonSurName")

    class Config:
        populate_by_name = True

class VehicleModel(BaseModel):
    make: Optional[str] = Field(default=None, alias="nc:VehicleMakeCode")
    model: Optional[str] = Field(default=None, alias="nc:VehicleModelCode")
    color: Optional[str] = Field(default=None, alias="nc:VehicleColorPrimaryCode")

    class Config:
        populate_by_name = True

class DocumentModel(BaseModel):
    size: Optional[int] = Field(default=None, alias="nc:BinarySizeValue")
    format: Optional[str] = Field(default=None, alias="nc:BinaryFormatText")
    hash_value: str = Field(alias="nc:HashValueText")
    hash_method: str = Field(alias="nc:HashMethodText")

    class Config:
        populate_by_name = True

class BiometricModel(BaseModel):
    category: str = Field(alias="biom:BiometricCategoryText")
    accuracy: Optional[float] = Field(default=None, alias="biom:BiometricAccuracyMeasure")
    status: Optional[str] = Field(default=None, alias="biom:BiometricStatusText")

    class Config:
        populate_by_name = True

# Main Combined Schema Blueprint
class NiemExtractionSchema(BaseModel):
    incident: IncidentModel = Field(alias="nc:Incident")
    person: Optional[PersonModel] = Field(default=None, alias="nc:Person")
    vehicle: Optional[VehicleModel] = Field(default=None, alias="nc:Vehicle")
    document: Optional[DocumentModel] = Field(default=None, alias="nc:Document")
    biometric: Optional[BiometricModel] = Field(default=None, alias="biom:Biometric")

    class Config:
        populate_by_name = True

# ==========================================
# 2. INCOMING REQUEST & ENDPOINT LOGIC
# ==========================================

class QueryRequest(BaseModel):
    prompt: str

# Target URL mapped directly to the local internal container hostname
LLM_API_URL = "http://sentinel-inference-node:8080/completion"

@router.post("/api/query")
async def process_niem_query(request: QueryRequest):
    # Generate the complete NIEM Schema with namespaces mapped dynamically
    niem_json_schema = NiemExtractionSchema.model_json_schema(by_alias=True)
    
    # Optional: Clean metadata title fields to lighten token space for strict GBNF matching
    niem_json_schema.pop("title", None)

    # Build execution payload matching llama-server specifications
    payload = {
    "messages": [
        {"role": "system", "content": "You are an advanced forensic intelligence engine. Extract investigative data matching the schema rules strictly from the target evidence text."},
        {"role": "user", "content": request.prompt}
    ],
    "temperature": 0.1,
    "response_format": {
        "type": "json_schema", 
        "json_schema": {"schema": niem_json_schema}
    }
}
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(LLM_API_URL, json=payload)
            
            if response.status_code != 200:
                logger.error(f"Inference node rejected transaction: {response.text}")
                raise HTTPException(status_code=500, detail="Inference engine execution error.")
            
            result_data = response.json()
            raw_content = result_data.get("content", "{}")
            
            # Direct text verification and local parsing check against our strict template
            validated_output = NiemExtractionSchema.model_validate_json(raw_content)

            logger.info(
                    "EVENT: NIEM_EXTRACTION_SUCCESS | "
                    "STATUS: 200 | "
                    "INFO: Inference node processed payload securely. CJI stripped from log."
                )
            
            # Dump output out to the central search broker preserving correct namespace keys
            return validated_output.model_dump(by_alias=True, exclude_none=True)
            
    except httpx.RequestError as e:
        logger.error(f"Failed to communicate with container node network: {str(e)}")
        raise HTTPException(status_code=500, detail="Inference node connection failure.")
    except Exception as e:
        logger.error(f"JSON Structure transformation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Output payload mismatch with validation metrics.")