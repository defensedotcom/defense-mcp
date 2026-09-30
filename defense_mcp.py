import os
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel, Field
import signal
import asyncio
import httpx
import random
import uuid
from training_templates import TRAINING_TEMPLATES
from mcp.server.fastmcp import FastMCP

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

logging.getLogger().handlers.clear()
handler = logging.StreamHandler()
handler.setLevel(logging.ERROR)
logging.getLogger().addHandler(handler)

class DetectionData(BaseModel):
    id: str = Field(..., description="Detection identifier")
    created_at: str = Field(..., description="Detection timestamp")
    updated_at: str = Field(..., description="Last updated timestamp")
    assets_count: int = Field(default=0, description="Number of affected assets in this detection event")
    users_count: int = Field(default=0, description="Number of affected users in this detection event")
    threat_id: Optional[str] = Field(None, description="The ID of the threat associated with this detection")
    threat_title: Optional[str] = Field(None, description="The title of the threat associated with this detection")
    threat_risk_score: Optional[str] = Field(None, description="The risk score of the threat associated with this detection")

class ThreatData(BaseModel):
    id: str = Field(..., description="Threat identifier")
    risk_score: str = Field(..., description="Risk score (critical, high, medium, low)")
    title: str = Field(..., description="Threat title")
    description: str = Field(..., description="Threat description")
    assets_count: int = Field(default=0, description="Number of affected assets")
    aasm_state: str = Field(..., description="Current state (detected, remediated, etc.)")
    created_at: str = Field(..., description="Creation timestamp")

class ThreatsResponse(BaseModel):
    threats: List[Dict[str, Any]] = Field(..., description="List of threat data")

def format_date_for_api(dt: datetime) -> str:
    """Format datetime for API date filters using RFC3339 format"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    elif dt.tzinfo != timezone.utc:
        dt = dt.astimezone(timezone.utc)
    
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_date_range_filters(days_back: int) -> Dict[str, str]:
    """Generate date filter parameters for API requests"""
    now = datetime.now(timezone.utc)
    cutoff_date = now - timedelta(days=days_back)
    
    return {
        "filter[after]": format_date_for_api(cutoff_date),
        "filter[before]": format_date_for_api(now)
    }

class DefenseClient:
    def __init__(self, api_token: str, base_url: str):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {api_token}", 
            "Accept": "application/json",
            "User-Agent": "Defense-MCP-Server/1.0.0"
        }
        self.client = httpx.AsyncClient(
            headers=self.headers, 
            timeout=60.0, 
            verify=True, 
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2)
        )
    
    async def get_threats(self, filters: Optional[Dict[str, Any]] = None, get_all_pages: bool = False) -> Dict[str, Any]:
        """Get threats with optional pagination"""
        url = f"{self.base_url}/v1/threats"
        params: Dict[str, Any] = {}
        
        if filters:
            # Handle different filter formats
            if any(k.startswith("filter[") for k in filters.keys()):
                params.update(filters)
            else:
                for k, v in filters.items():
                    params[f"params[filter][{k}]"] = v
        
        try:
            if not get_all_pages:
                logger.debug(f"Making API request to {url} with params: {params}")
                response = await self.client.get(url, params=params)
                response.raise_for_status()
                
                content_type = response.headers.get("Content-Type", "")
                if "application/json" not in content_type:
                    raise RuntimeError(f"Expected JSON response, got {content_type}")
                
                data = response.json()
                logger.debug(f"API response received: {len(data.get('results', []))} threats")
                return data
            else:
                # Get all pages
                all_results = []
                page = 1
                total_pages = None
                
                while True:
                    # Add page parameter
                    page_params = params.copy()
                    page_params['page'] = page
                    
                    logger.debug(f"Fetching page {page} from {url} with params: {page_params}")
                    response = await self.client.get(url, params=page_params)
                    response.raise_for_status()
                    
                    content_type = response.headers.get("Content-Type", "")
                    if "application/json" not in content_type:
                        raise RuntimeError(f"Expected JSON response, got {content_type}")
                    
                    data = response.json()
                    page_results = data.get('results', [])
                    all_results.extend(page_results)
                    
                    # Get pagination info from first response
                    if total_pages is None:
                        total_pages = data.get('total_pages', 1)
                        logger.debug(f"Total pages: {total_pages}, current page: {page}")
                    
                    if page >= total_pages or len(page_results) == 0:
                        break
                    
                    page += 1
                    
                    # Safety check to prevent infinite loops
                    if page > 1000:
                        logger.warning("Reached maximum page limit (1000), stopping pagination")
                        break
                
                return {
                    'results': all_results,
                    'page': 1,
                    'per_page': len(all_results),
                    'total_pages': total_pages or 1,
                    'total_count': len(all_results)
                }
                
        except httpx.TimeoutException:
            logger.error("API request timed out")
            raise RuntimeError("Defense API request timed out - please try again")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                resp_text = (e.response.text or "").lower()
                if "revoked" in resp_text or "expired" in resp_text:
                    error_detail = "Your API key was rejected (revoked or expired). Please update DEFENSE_API_TOKEN in your connector settings and restart Claude Desktop."
                else:
                    error_detail = "Authentication failed (401). If you recently updated your DEFENSE_API_TOKEN, please fully restart Claude Desktop for the change to take effect."
                logger.error(f"HTTP error 401: {e.response.text} - {error_detail}")
                raise RuntimeError(error_detail) from e
            logger.error(f"HTTP error ({e.response.status_code}): {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in API request: {e}")
            raise

    async def get_threat_by_id(self, threat_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific threat by ID"""
        url = f"{self.base_url}/v1/threats/{threat_id}"
        
        try:
            logger.debug(f"Making API request to {url}")
            response = await self.client.get(url)
            response.raise_for_status()
            
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                raise RuntimeError(f"Expected JSON response, got {content_type}")
            
            data = response.json()
            logger.debug(f"API response received for threat {threat_id}")
            return data
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.debug(f"Threat {threat_id} not found")
                return None
            if e.response.status_code == 401:
                resp_text = (e.response.text or "").lower()
                if "revoked" in resp_text or "expired" in resp_text:
                    error_detail = "Your API key was rejected (revoked or expired). Please update DEFENSE_API_TOKEN in your connector settings and restart Claude Desktop."
                else:
                    error_detail = "Authentication failed (401). If you recently updated your DEFENSE_API_TOKEN, please fully restart Claude Desktop for the change to take effect."
                logger.error(f"HTTP error 401: {e.response.text} - {error_detail}")
                raise RuntimeError(error_detail) from e
            logger.error(f"HTTP error ({e.response.status_code}): {e.response.text}")
            raise
        except httpx.TimeoutException:
            logger.error("API request timed out")
            raise RuntimeError("Defense API request timed out - please try again")
        except Exception as e:
            logger.error(f"Unexpected error in API request: {e}")
            raise

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


api_token = os.getenv("DEFENSE_API_TOKEN")
base_url = os.getenv("DEFENSE_API_BASE_URL")

if not api_token:
    raise ValueError("DEFENSE_API_TOKEN environment variable is required")

if not base_url:
    raise ValueError("DEFENSE_API_BASE_URL environment variable is required")

logger.info(f"Using DEFENSE_API_BASE_URL: {base_url}")

defense_client = None

mcp = FastMCP(
    "Defense MCP"
)

class TrainingQuestion(BaseModel):
    question: str = Field(..., description="The training question")
    question_type: str = Field(..., description="Type of question (identification, response, prevention)")
    difficulty: str = Field(..., description="Difficulty level (beginner, intermediate, advanced)")
    context: Optional[str] = Field(None, description="Additional context for the question")
    hints: List[str] = Field(default_factory=list, description="Hints to help answer the question")

class TrainingModule(BaseModel):
    title: str = Field(..., description="Training module title")
    description: str = Field(..., description="Module description")
    questions: List[TrainingQuestion] = Field(..., description="List of training questions")
    threat_context: Optional[Dict[str, Any]] = Field(None, description="Related threat information")

class TrainingSession(BaseModel):
    session_id: str = Field(..., description="Unique session identifier")
    user_id: Optional[str] = Field(None, description="User identifier")
    current_question: int = Field(default=0, description="Current question index")
    questions: List[TrainingQuestion] = Field(..., description="Session questions")
    responses: List[Dict[str, Any]] = Field(default_factory=list, description="User responses")
    score: int = Field(default=0, description="Current score")
    started_at: str = Field(..., description="Session start time")
    completed: bool = Field(default=False, description="Session completion status")

training_sessions: Dict[str, TrainingSession] = {}

THREAT_KEYWORDS = {
    "ransomware": {"ransomware", "encrypt", "ransom", "crypto"},
    "malware": {"malware", "virus", "trojan", "worm", "backdoor"},
    "phishing": {"phish", "email", "social engineer", "spam"},
    "vulnerability_management": {"vulnerability", "cve", "patch", "exploit", "rce", "dos"},
    "network_security": {"tcp", "smb", "network", "protocol", "server"}
}

def categorize_threat(content: str) -> str:
    """Categorize threat based on content keywords"""
    content_lower = content.lower()
    
    for category, keywords in THREAT_KEYWORDS.items():
        if any(keyword in content_lower for keyword in keywords):
            return category
    
    return "general"

def parse_rfc3339_date(date_string: str) -> Optional[datetime]:
    """Parse RFC 3339/ISO 8601 date string to datetime object"""
    if not date_string:
        return None
    
    try:
        clean_date = date_string.replace("Z", "+00:00")
        
        dt = datetime.fromisoformat(clean_date)
        
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            
        return dt
    except ValueError:
        # Fallback for edge cases
        try:
            base_date = date_string.split("+")[0].split("Z")[0].split(".")[0]
            return datetime.strptime(base_date, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            logger.debug(f"Could not parse date: {date_string}")
            return None

_client_lock = asyncio.Lock()

async def get_defense_client():
    global defense_client
    if defense_client is None:
        async with _client_lock:
            if defense_client is None:
                await initialize_defense_client()
    return defense_client

async def initialize_defense_client():
    global defense_client
    if defense_client is None:
        logger.info("Initializing Defense API client...")
        
        if not api_token or not base_url:
            raise ValueError("Missing required environment variables: DEFENSE_API_TOKEN and DEFENSE_API_BASE_URL")
        
        defense_client = DefenseClient(api_token, base_url)
        
        try:
            await defense_client.get_threats({"limit": 1})
            logger.info("Defense API client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to connect to Defense API: {e}")
            await defense_client.close()
            defense_client = None
            raise

async def health_check() -> bool:
    """Check if the Defense API is accessible"""
    try:
        defense_client = await get_defense_client()
        response = await defense_client.get_threats({"limit": 1})
        return True
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return False

@mcp.tool()
async def get_biggest_risks() -> Dict[str, Any]:
    """Get the biggest security risks based on risk score and other factors"""
    global defense_client
    try:
        defense_client = await get_defense_client()
        
        logger.info("Fetching biggest security risks...")
        
        # Get critical and high threats - use pagination to ensure we get all
        critical_threats = await defense_client.get_threats({"risk_score": "critical"}, get_all_pages=True)
        high_threats = await defense_client.get_threats({"risk_score": "high"}, get_all_pages=True)
        
        all_threats = critical_threats.get("results", []) + high_threats.get("results", [])
        
        # Remove duplicates using dictionary comprehension
        unique_threats = list({threat.get("id"): threat for threat in all_threats if threat.get("id")}.values())
        
        if not unique_threats:
            return {
                "threats": [],
                "message": "No critical or high-risk threats found in your environment.",
                "total_count": 0
            }
        
        sorted_threats = sorted(
            unique_threats,
            key=lambda t: (
                0 if t.get("risk_score") == "critical" else 1,
                -1 * t.get("assets_count", 0)
            )
        )
        
        top_threats = sorted_threats[:5]
        
        return {
            "threats": top_threats,
            "message": f"Found {len(top_threats)} top threats out of {len(unique_threats)} total high/critical threats.",
            "total_count": len(unique_threats),
            "pages_checked": f"Critical: {critical_threats.get('total_pages', 1)}, High: {high_threats.get('total_pages', 1)}"
        }
        
    except httpx.HTTPStatusError as e:
        error_msg = f"API request failed: {e.response.status_code}"
        if e.response.status_code == 401:
            resp_text = (e.response.text or "").lower()
            if "revoked" in resp_text or "expired" in resp_text:
                error_msg += " - Your API key was rejected (revoked or expired). Please update DEFENSE_API_TOKEN in your connector settings and restart Claude Desktop."
            else:
                error_msg += " - Please check your API token. If you recently updated your token, remember to fully restart Claude Desktop for the change to take effect."
        elif e.response.status_code == 403:
            error_msg += " - API token lacks required permissions"
        logger.error(error_msg)
        return {"error": error_msg, "threats": []}
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg, "threats": []}

@mcp.tool()
async def get_threat_to_remediate_first(days: int = 1) -> Dict[str, Any]:
    """Determine which threat should be remediated first"""
    global defense_client
    try:
        defense_client = await get_defense_client()
        
        # Use pagination to get all threats
        all_threats = await defense_client.get_threats(get_all_pages=True)
        threats_list = all_threats.get("results", [])
        
        unremediated = [t for t in threats_list if t.get("aasm_state") == "detected"]
        
        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        sorted_threats = sorted(
            unremediated,
            key=lambda t: (
                risk_order.get(t.get("risk_score", "low"), 0),
                t.get("assets_count", 0)
            ),
            reverse=True
        )
        
        if sorted_threats:
            threats_response = ThreatsResponse(threats=[sorted_threats[0]])
        else:
            threats_response = ThreatsResponse(threats=[])
        return threats_response.model_dump()
        
    except Exception as e:
        error_msg = f"Failed to get threat to remediate first: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg, "threats": []}

@mcp.tool()
async def get_new_threats(days: int = 1) -> Dict[str, Any]:
    """Get new security threats from the last n days"""
    if days < 1 or days > 365:
        return {
            "error": "Days parameter must be between 1 and 365",
            "threats": []
        }
    
    global defense_client
    try:
        defense_client = await get_defense_client()
        logger.info(f"Fetching threats from last {days} days using date filters...")
        
        date_filters = get_date_range_filters(days)
        logger.info(f"Using date filters: {date_filters}")
        
        recent_threats_response = await defense_client.get_threats(date_filters, get_all_pages=True)
        recent_threats = recent_threats_response.get("results", [])
        
        logger.info(f"Retrieved {len(recent_threats)} threats using server-side date filters")
        
        # Sort by creation date (newest first)
        recent_threats.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        threats_response = ThreatsResponse(threats=recent_threats)
        response_dict = threats_response.model_dump()
        
        cutoff_date = datetime.now() - timedelta(days=days)
        response_dict.update({
            "total_count": len(recent_threats),
            "days_requested": days,
            "cutoff_date": cutoff_date.isoformat(),
            "pages_fetched": recent_threats_response.get("total_pages", "unknown"),
            "filtering_method": "server_side_date_filters"
        })
        
        if len(recent_threats) == 0:
            response_dict["message"] = f"No threats found in the last {days} days using server-side date filters"
        else:
            newest_date = recent_threats[0].get("created_at") if recent_threats else "unknown"
            response_dict["message"] = f"Found {len(recent_threats)} threats from the last {days} days (newest: {newest_date})"
        
        return response_dict
        
    except Exception as e:
        error_msg = f"Failed to get new threats: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg, "threats": []}

@mcp.tool()
async def get_latest_detections(days: int = 1, threat_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get the latest detection events from the last N days.
    Optionally, filter detections for a specific threat ID.
    Includes the total count of detections for a given threat if threat_id is provided.
    """
    if days < 1 or days > 365:
        return {
            "error": "Days parameter must be between 1 and 365",
            "detections": []
        }
    
    global defense_client
    try:
        defense_client = await get_defense_client()
        
        if threat_id:
            logger.info(f"Fetching all threats to find specific threat {threat_id} and check detections from last {days} days...")
            all_threats_response = await defense_client.get_threats(get_all_pages=True)
            all_threats = all_threats_response.get("results", [])
        else:
            logger.info(f"Fetching threats from last {days} days using date filters to find latest detections...")
            date_filters = get_date_range_filters(days)
            logger.info(f"Using date filters: {date_filters}")
            
            all_threats_response = await defense_client.get_threats(date_filters, get_all_pages=True)
            all_threats = all_threats_response.get("results", [])

        recent_detections = []
        cutoff_date = datetime.now() - timedelta(days=days)

        target_threat_total_detections = None
        target_threat_title = None
        target_threat_risk_score = None

        for threat in all_threats:
            if threat_id and threat.get("id") != threat_id:
                continue # Skip if threat_id is specified and doesn't match

            if threat_id and threat.get("id") == threat_id:
                target_threat_total_detections = threat.get("detections_count", 0)
                target_threat_title = threat.get("title")
                target_threat_risk_score = threat.get("risk_score")

            latest_detection_data = threat.get("latest_detection")
            if latest_detection_data:
                created_at_str = latest_detection_data.get("created_at")
                if not created_at_str:
                    continue
                
                threat_date = parse_rfc3339_date(created_at_str)
                
                if threat_date and threat_date >= cutoff_date:
                        detection_entry = DetectionData(
                            id=latest_detection_data.get("id"),
                            created_at=latest_detection_data.get("created_at"),
                            updated_at=latest_detection_data.get("updated_at"),
                            assets_count=latest_detection_data.get("assets_count", 0),
                            users_count=latest_detection_data.get("users_count", 0),
                            threat_id=threat.get("id"),
                            threat_title=threat.get("title"),
                            threat_risk_score=threat.get("risk_score")
                        )
                        recent_detections.append(detection_entry.model_dump())
        
        recent_detections.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        filtering_method = "server_side_date_filters" if not threat_id else "full_scan_for_specific_threat"
        response_dict = {
            "detections": recent_detections,
            "total_count": len(recent_detections),
            "days_requested": days,
            "cutoff_date": cutoff_date.isoformat(),
            "filtering_method": filtering_method,
            "message": f"Found {len(recent_detections)} latest detection events from the last {days} days."
        }

        if threat_id:
            response_dict["threat_context"] = {
                "id": threat_id,
                "title": target_threat_title,
                "risk_score": target_threat_risk_score,
                "total_detections_on_threat": target_threat_total_detections,
                "message": f"Total detections for threat '{target_threat_title}' (ID: {threat_id}): {target_threat_total_detections}."
            }
            if not target_threat_total_detections is None and len(recent_detections) == 0:
                 response_dict["message"] = f"No new detections for threat '{target_threat_title}' (ID: {threat_id}) in the last {days} days, but it has {target_threat_total_detections} total detections."


        return response_dict
        
    except Exception as e:
        error_msg = f"Failed to get latest detections: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg, "detections": []}

@mcp.tool()
async def get_threats_by_assignee(assignee_email: str) -> Dict[str, Any]:
    """Get all threats assigned to a specific person"""
    global defense_client
    try:
        defense_client = await get_defense_client()
        all_threats = await defense_client.get_threats(get_all_pages=True)
        threats_list = all_threats.get("results", [])
        
        assigned_threats = []
        for threat in threats_list:
            remediations = threat.get("remediations", [])
            for remediation in remediations:
                if remediation.get("assigned_to") == assignee_email:
                    assigned_threats.append(threat)
                    break
        
        return {
            "assignee": assignee_email,
            "total_assigned": len(assigned_threats),
            "threats": assigned_threats,
            "by_risk": {
                "critical": len([t for t in assigned_threats if t.get("risk_score") == "critical"]),
                "high": len([t for t in assigned_threats if t.get("risk_score") == "high"]),
                "medium": len([t for t in assigned_threats if t.get("risk_score") == "medium"]),
                "low": len([t for t in assigned_threats if t.get("risk_score") == "low"])
            }
        }
    except Exception as e:
        error_msg = f"Failed to get threats for assignee: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg}

@mcp.tool()
async def get_threats_by_source(source_type: str) -> Dict[str, Any]:
    """Get threats filtered by source type"""
    global defense_client
    try:
        defense_client = await get_defense_client()
        all_threats = await defense_client.get_threats(get_all_pages=True)
        threats_list = all_threats.get("results", [])
        
        source_threats = [t for t in threats_list if t.get("source_type") == source_type]
        
        return {
            "source_type": source_type,
            "total_threats": len(source_threats),
            "threats": source_threats,
            "risk_breakdown": {
                "critical": len([t for t in source_threats if t.get("risk_score") == "critical"]),
                "high": len([t for t in source_threats if t.get("risk_score") == "high"]),
                "medium": len([t for t in source_threats if t.get("risk_score") == "medium"]),
                "low": len([t for t in source_threats if t.get("risk_score") == "low"])
            }
        }
    except Exception as e:
        error_msg = f"Failed to get threats by source: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg}

@mcp.tool()
async def get_workload_analysis(days: Optional[int] = None) -> Dict[str, Any]:
    """
    Analyze current threat workload and assignments, providing a dashboard-like overview
    of active (incomplete) threats by risk score and overall threat distribution.
    If days is specified, only analyzes threats from the last N days for more focused analysis.
    """
    if days is not None and (days < 1 or days > 365):
        return {
            "error": "Days parameter must be between 1 and 365, or omit for all threats",
            "workload": {}
        }
    
    global defense_client
    try:
        defense_client = await get_defense_client()
        
        if days:
            logger.info(f"Analyzing workload for threats from last {days} days using date filters...")
            date_filters = get_date_range_filters(days)
            all_threats_response = await defense_client.get_threats(date_filters, get_all_pages=True)
            filtering_method = "server_side_date_filters"
        else:
            logger.info("Analyzing workload for all threats...")
            all_threats_response = await defense_client.get_threats(get_all_pages=True)
            filtering_method = "all_threats"
            
        threats_list = all_threats_response.get("results", [])

        assignee_workload = {}
        unassigned_count = 0

        # Dashboard-like metrics
        active_threats_count = 0
        active_risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_accepted": 0}
        overall_risk_analysis = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "risk_accepted": 0}
        overall_state_analysis = {"detected": 0, "remediated": 0, "false_positive": 0, "assigned": 0, "risk_accepted": 0}

        complete_states = ["remediated", "false_positive", "risk_accepted", "compensating_control"]

        for threat in threats_list:
            risk_score = threat.get("risk_score", "low")
            aasm_state = threat.get("aasm_state", "detected")

            overall_risk_analysis[risk_score] += 1
            overall_state_analysis[aasm_state] += 1

            # Check if threat is "active" (i.e., "incomplete" based on portal's filter)
            if aasm_state not in complete_states:
                active_threats_count += 1
                active_risk_distribution[risk_score] += 1

            remediations = threat.get("remediations", [])
            if not remediations:
                unassigned_count += 1
                continue

            assigned = False
            for remediation in remediations:
                assignee = remediation.get("assigned_to")
                if not assignee:
                    continue
                
                assigned = True
                if assignee not in assignee_workload:
                    assignee_workload[assignee] = {
                        "total": 0,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                        "detected": 0,
                        "remediated": 0
                    }
                
                workload = assignee_workload[assignee]
                workload["total"] += 1
                workload[risk_score] += 1
                state = remediation.get("aasm_state")
                workload["detected" if state == "detected" else "remediated"] += 1
            
            if not assigned:
                unassigned_count += 1

        threats_older_than_30_days_active = 0
        current_date_utc = datetime.now(timezone.utc)

        for threat in threats_list:
            if threat.get("aasm_state") not in complete_states:
                created_at_str = threat.get("created_at")
                if created_at_str:
                    try:
                        threat_date = parse_rfc3339_date(created_at_str)
                        
                        if threat_date:
                            current_date_naive = current_date_utc.replace(tzinfo=None)
                            if (current_date_naive - threat_date).days > 30:
                                threats_older_than_30_days_active += 1
                    except Exception as parse_error:
                        logger.debug(f"Could not parse date {created_at_str} for age calculation: {parse_error}")
                        continue

        analysis_scope = f"last {days} days" if days else "all time"
        
        return {
            "analysis_scope": analysis_scope,
            "filtering_method": filtering_method,
            "total_threats_analyzed": len(threats_list),
            "active_threats_summary": {
                "total_active_threats": active_threats_count,
                "threats_older_than_30_days": threats_older_than_30_days_active,
                "risk_breakdown": active_risk_distribution
            },
            "overall_threat_distribution": {
                "risk_scores": overall_risk_analysis,
                "states": overall_state_analysis
            },
            "workload_by_assignee": assignee_workload,
            "unassigned_threats": unassigned_count,
            "recommendations": [
                f"Consider addressing the {active_risk_distribution['critical']} critical incomplete threats immediately.",
                f"Focus on remediating the {threats_older_than_30_days_active} incomplete threats that are older than 30 days.",
                f"Review the {unassigned_count} unassigned threats to ensure timely remediation." if unassigned_count > 0 else "All threats are assigned or being managed."
            ]
        }

    except Exception as e:
        error_msg = f"Failed to analyze workload and generate dashboard view: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg}

@mcp.tool()
async def search_threats_by_keyword(keyword: str, include_description: bool = True) -> Dict[str, Any]:
    """Search for threats containing specific keywords in title or description"""
    global defense_client
    try:
        defense_client = await get_defense_client()
        all_threats = await defense_client.get_threats(get_all_pages=True)
        threats_list = all_threats.get("results", [])
        
        keyword_lower = keyword.lower()
        matching_threats = []
        
        for threat in threats_list:
            title = threat.get("title", "").lower()
            description = threat.get("description", "").lower() if include_description else ""
            
            if keyword_lower in title or (include_description and keyword_lower in description):
                matching_threats.append(threat)
        
        return {
            "search_keyword": keyword,
            "searched_description": include_description,
            "total_matches": len(matching_threats),
            "threats": matching_threats,
            "match_summary": {
                "critical": len([t for t in matching_threats if t.get("risk_score") == "critical"]),
                "high": len([t for t in matching_threats if t.get("risk_score") == "high"]),
                "medium": len([t for t in matching_threats if t.get("risk_score") == "medium"]),
                "low": len([t for t in matching_threats if t.get("risk_score") == "low"])
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to search threats: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg}

@mcp.tool()
async def get_threat_details_with_context(threat_id: str) -> Dict[str, Any]:
    """Get comprehensive threat details including assets, users, and detections"""
    global defense_client
    try:
        defense_client = await get_defense_client()
        threat_data = await defense_client.get_threat_by_id(threat_id)
        if not threat_data:
            return {"error": f"Threat {threat_id} not found"}
        
        assets_url = f"{defense_client.base_url}/v1/threats/{threat_id}/assets"
        try:
            assets_response = await defense_client.client.get(assets_url)
            assets_response.raise_for_status()
            assets_data = assets_response.json()
        except:
            assets_data = {"results": []}
        
        users_url = f"{defense_client.base_url}/v1/threats/{threat_id}/users"
        try:
            users_response = await defense_client.client.get(users_url)
            users_response.raise_for_status()
            users_data = users_response.json()
        except:
            users_data = {"results": []}
        
        detections_url = f"{defense_client.base_url}/v1/threats/{threat_id}/detections"
        try:
            detections_response = await defense_client.client.get(detections_url)
            detections_response.raise_for_status()
            detections_data = detections_response.json()
        except:
            detections_data = {"results": []}
        
        return {
            "threat": threat_data,
            "affected_assets": {
                "count": len(assets_data.get("results", [])),
                "assets": assets_data.get("results", [])
            },
            "affected_users": {
                "count": len(users_data.get("results", [])),
                "users": users_data.get("results", [])
            },
            "detections": {
                "count": len(detections_data.get("results", [])),
                "detections": detections_data.get("results", [])
            },
            "summary": {
                "threat_id": threat_id,
                "title": threat_data.get("title"),
                "risk_score": threat_data.get("risk_score"),
                "state": threat_data.get("aasm_state"),
                "total_impact": {
                    "assets": len(assets_data.get("results", [])),
                    "users": len(users_data.get("results", [])),
                    "detections": len(detections_data.get("results", []))
                }
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to get threat details: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg}

@mcp.tool()
async def generate_training_questions(
    threat_id: Optional[str] = None,
    threat_type: Optional[str] = None,
    difficulty: str = "intermediate",
    count: int = 3
) -> Dict[str, Any]:
    """Generate training questions based on current threats or specific threat types"""
    
    if count < 1 or count > 10:
        return {
            "error": "Question count must be between 1 and 10",
            "questions": []
        }
    
    global defense_client
    try:
        defense_client = await get_defense_client()
        
        training_context = None
        question_pool = []
        
        if threat_id:
            threats = await defense_client.get_threats(get_all_pages=True)
            threat = next((t for t in threats.get("results", []) if t.get("id") == threat_id), None)
            if threat:
                training_context = threat
                threat_content = f"{threat.get('title', '')} {threat.get('description', '')}".lower()
                threat_category = categorize_threat(threat_content)
                if threat_category in TRAINING_TEMPLATES:
                    question_pool.extend(TRAINING_TEMPLATES[threat_category]["questions"])
        
        # If threat type specified, use those questions
        elif threat_type and threat_type.lower() in TRAINING_TEMPLATES:
            question_pool.extend(TRAINING_TEMPLATES[threat_type.lower()]["questions"])
        
        # Default to general questions if no specific context
        if not question_pool:
            for category in TRAINING_TEMPLATES.values():
                question_pool.extend(category["questions"])
        
        # Filter by difficulty if specified
        if difficulty != "all":
            question_pool = [q for q in question_pool if q["difficulty"] == difficulty]
        
        # Randomly select questions
        selected_questions = random.sample(
            question_pool, 
            min(count, len(question_pool))
        ) if question_pool else []
        
        training_module = TrainingModule(
            title=f"Security Training - {threat_type.title() if threat_type else 'General'}",
            description=f"Training questions based on {'current threat' if threat_id else threat_type if threat_type else 'general security concepts'}",
            questions=[TrainingQuestion(**q) for q in selected_questions],
            threat_context=training_context
        )
        
        return training_module.model_dump()
        
    except Exception as e:
        error_msg = f"Failed to generate training questions: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg, "questions": []}

@mcp.tool()
async def get_training_for_threat(threat_id: str) -> Dict[str, Any]:
    """Get specific training content for a particular threat"""
    global defense_client
    try:
        defense_client = await get_defense_client()
        
        # Try multiple approaches to find the threat
        threat = None
        
        logger.debug(f"Searching for threat ID: {threat_id}")
        
        threat = await defense_client.get_threat_by_id(threat_id)
        
        if not threat:
            return {
                "error": f"Threat with ID {threat_id} not found. The threat may not exist or may not be accessible through the current API permissions.",
                "training": None,
                "debug_info": {
                    "searched_threat_id": threat_id
                }
            }
        
        logger.debug(f"Found threat: {threat.get('title')}")
        
        threat_content = f"{threat.get('title', '')} {threat.get('description', '')}"
        
        training_type = categorize_threat(threat_content)
        
        # Generate training questions
        training_result = await generate_training_questions(
            threat_id=threat_id,
            threat_type=training_type,
            count=5
        )
        
        return {
            "threat_details": {
                "id": threat.get("id"),
                "title": threat.get("title"),
                "risk_score": threat.get("risk_score"),
                "description": threat.get("description"),
                "aasm_state": threat.get("aasm_state"),
                "assets_count": threat.get("assets_count", 0),
                "created_at": threat.get("created_at")
            },
            "training_type": training_type,
            "training_module": training_result,
            "remediation_status": "This threat has been remediated" if threat.get("aasm_state") == "remediated" else "This threat is currently active"
        }
        
    except Exception as e:
        error_msg = f"Failed to get training for threat: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg}

@mcp.tool()
async def get_security_awareness_brief() -> Dict[str, Any]:
    """Generate a security awareness briefing based on current threat landscape"""
    global defense_client
    try:
    
        # Get recent threats for context
        recent_threats = await get_new_threats(days=7)
        top_risks = await get_biggest_risks()
        
        # Analyze threat patterns
        all_threats = recent_threats.get("threats", []) + top_risks.get("threats", [])
        
        unique_threats = list({threat.get("id"): threat for threat in all_threats if threat.get("id")}.values())
        
        threat_types = {}
        for threat in unique_threats:
            content = f"{threat.get('title', '')} {threat.get('description', '')}"
            
            threat_category = categorize_threat(content)
            threat_types[threat_category] = threat_types.get(threat_category, 0) + 1
        
        # Generate training recommendations
        top_threat_type = max(threat_types.items(), key=lambda x: x[1])[0] if threat_types else 'general'
        
        # Create awareness brief
        brief = {
            "period": "Last 7 days",
            "threat_summary": {
                "total_threats": len(unique_threats),
                "threat_breakdown": threat_types,
                "primary_concern": top_threat_type
            },
            "recommended_training": await generate_training_questions(
                threat_type=top_threat_type,
                count=3,
                difficulty="intermediate"
            ),
            "key_reminders": [
                "Always verify sender identity before clicking links or downloading attachments",
                "Keep systems and software updated with latest security patches",
                "Report suspicious activity immediately to the security team",
                "Use strong, unique passwords with multi-factor authentication",
                "Regular backups are your best defense against ransomware"
            ],
            "emergency_contacts": {
                "security_team": "security@defense.com"
            }
        }
        
        return brief
        
    except Exception as e:
        error_msg = f"Failed to generate security awareness brief: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg}

@mcp.tool()
async def start_training_session(
    threat_id: Optional[str] = None,
    difficulty: str = "intermediate",
    session_type: str = "general"
) -> Dict[str, Any]:
    """Start an interactive training session"""
    
    session_id = str(uuid.uuid4())[:8]
    
    # Generate questions for the session
    training_data = await generate_training_questions(
        threat_id=threat_id,
        threat_type=session_type,
        difficulty=difficulty,
        count=5
    )
    
    if "error" in training_data:
        return training_data
    
    session = TrainingSession(
        session_id=session_id,
        questions=training_data.get("questions", []),
        started_at=datetime.now().isoformat()
    )
    
    training_sessions[session_id] = session
    
    # Return first question
    if session.questions:
        first_question = session.questions[0]
        return {
            "session_id": session_id,
            "total_questions": len(session.questions),
            "current_question": 1,
            "question": first_question.model_dump(),
            "progress": f"1/{len(session.questions)}",
            "instructions": [
                "Answer each question to the best of your ability",
                "You can ask for hints if needed",
                "Type your answer when ready to proceed"
            ]
        }
    else:
        return {"error": "No questions available for this training session"}

@mcp.tool()
async def get_training_hint(session_id: str) -> Dict[str, Any]:
    """Get a hint for the current training question"""
    
    if session_id not in training_sessions:
        return {"error": "Training session not found"}
    
    session = training_sessions[session_id]
    
    if session.completed:
        return {"error": "Training session already completed"}
    
    if session.current_question >= len(session.questions):
        return {"error": "No current question"}
    
    current_q = session.questions[session.current_question]
    
    if not current_q.hints:
        return {"message": "No hints available for this question"}
    
    # Return a random hint
    hint = random.choice(current_q.hints)
    
    return {
        "hint": hint,
        "question": current_q.question,
        "remaining_hints": len(current_q.hints) - 1
    }

@mcp.tool()
async def submit_training_answer(
    session_id: str, 
    answer: str,
    request_next: bool = True
) -> Dict[str, Any]:
    """Submit an answer to a training question and optionally get the next question"""
    
    if session_id not in training_sessions:
        return {"error": "Training session not found"}
    
    session = training_sessions[session_id]
    
    if session.completed:
        return {"error": "Training session already completed"}
    
    if session.current_question >= len(session.questions):
        return {"error": "No more questions in this session"}
    
    # Record the answer
    current_q = session.questions[session.current_question]
    response_data = {
        "question": current_q.question,
        "user_answer": answer,
        "timestamp": datetime.now().isoformat(),
        "question_type": current_q.question_type,
        "difficulty": current_q.difficulty
    }
    
    session.responses.append(response_data)
    
    # Move to next question
    session.current_question += 1
    
    # Check if session is complete
    if session.current_question >= len(session.questions):
        session.completed = True
        
        return {
            "session_completed": True,
            "total_questions": len(session.questions),
            "responses_recorded": len(session.responses),
            "session_summary": {
                "started_at": session.started_at,
                "completed_at": datetime.now().isoformat(),
                "question_types_covered": list(set(r["question_type"] for r in session.responses)),
                "difficulty_levels": list(set(r["difficulty"] for r in session.responses))
            },
            "message": "Great job completing the training session! Your responses have been recorded for review."
        }
    
    # Return next question if requested
    if request_next:
        next_question = session.questions[session.current_question]
        return {
            "answer_recorded": True,
            "current_question": session.current_question + 1,
            "total_questions": len(session.questions),
            "question": next_question.model_dump(),
            "progress": f"{session.current_question + 1}/{len(session.questions)}"
        }
    else:
        return {
            "answer_recorded": True,
            "message": "Answer recorded. Ask for the next question when ready."
        }

@mcp.tool()
async def get_training_session_status(session_id: str) -> Dict[str, Any]:
    """Get the current status of a training session"""
    
    if session_id not in training_sessions:
        return {"error": "Training session not found"}
    
    session = training_sessions[session_id]
    
    return {
        "session_id": session_id,
        "completed": session.completed,
        "current_question": session.current_question + 1 if not session.completed else "Complete",
        "total_questions": len(session.questions),
        "questions_answered": len(session.responses),
        "started_at": session.started_at,
        "progress_percentage": round((len(session.responses) / len(session.questions)) * 100, 1) if session.questions else 0
    }


async def cleanup():
    global defense_client
    if defense_client:
        logger.info("Closing Defense API client...")
        await defense_client.close()
        defense_client = None
        logger.info("Defense API client closed")

async def shutdown_handler():
    """Handle graceful shutdown"""
    logger.info("Received shutdown signal, cleaning up...")
    await cleanup()
    logger.info("Cleanup completed")

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, _):
        print(f"\nReceived signal {signum}, shutting down...")
        asyncio.create_task(shutdown_handler())
        exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

__version__ = "1.0.0"
__author__ = "Defense.com"
__description__ = "MCP Server for Defense.com Threat Portal API"

if __name__ == "__main__":
    try:
        setup_signal_handlers()
        logger.info(f"Starting Defense MCP Server v{__version__}...")
        mcp.run()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Error starting MCP server: {str(e)}")
        exit(1)