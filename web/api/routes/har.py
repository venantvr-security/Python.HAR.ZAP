"""
HAR Upload and Processing API Routes
"""
from fastapi import APIRouter, HTTPException, Request, UploadFile, File
from pydantic import BaseModel
from typing import Optional, Dict, List

router = APIRouter()


class PreprocessRequest(BaseModel):
    exclude_static: Optional[bool] = True
    methods: Optional[List[str]] = None
    domains: Optional[List[str]] = None


@router.post("/upload")
async def upload_har(request: Request, file: UploadFile = File(...)):
    """Upload and parse HAR file"""
    har_service = request.app.state.shared['har_service']

    if not file.filename.endswith('.har'):
        raise HTTPException(status_code=400, detail="File must be .har")

    content = await file.read()

    try:
        summary = har_service.load_har(content)
        return {
            "status": "loaded",
            "filename": file.filename,
            **summary
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid HAR: {str(e)}")


@router.post("/preprocess")
async def preprocess_har(request: Request, preprocess: PreprocessRequest = None):
    """Preprocess loaded HAR"""
    har_service = request.app.state.shared['har_service']

    if not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded")

    filters = {}
    if preprocess:
        if preprocess.exclude_static is not None:
            filters['exclude_static'] = preprocess.exclude_static
        if preprocess.methods:
            filters['methods'] = preprocess.methods
        if preprocess.domains:
            filters['domains'] = preprocess.domains

    result = har_service.preprocess(filters)
    return result


@router.get("/summary")
async def get_summary(request: Request):
    """Get summary of loaded HAR"""
    har_service = request.app.state.shared['har_service']
    return har_service.get_summary()


@router.get("/endpoints")
async def get_endpoints(request: Request):
    """Get preprocessed endpoints"""
    har_service = request.app.state.shared['har_service']
    return {"endpoints": har_service.get_endpoints()}


@router.get("/urls")
async def get_urls(request: Request):
    """Get unique URLs from HAR"""
    har_service = request.app.state.shared['har_service']
    return {"urls": har_service.get_urls()}
