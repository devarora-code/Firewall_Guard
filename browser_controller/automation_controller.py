"""
🤖 Browser Automation Test Controller
Controls Chrome extension for automated browser testing
"""

import requests
import json
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional
import threading
import websocket
import logging

class BrowserAutomationController:
    def __init__(self, extension_id: str = None):
        self.extension_id = extension_id
        self.base_url = "http://localhost:5000"
        self.sessions = {}
        self.ws_connections = {}
        self.logger = logging.getLogger(__name__)
        
    def connect_to_extension(self, extension_id: str):
        """Connect to Chrome extension"""
        self.extension_id = extension_id
        self.logger.info(f"Connected to extension {extension_id}")
        
    async def start_automation_session(self, config: Dict = None) -> str:
        """Start a new browser automation session"""
        if not self.extension_id:
            raise Exception("Extension not connected")
        
        config = config or {
            "startUrl": "about:blank",
            "closeTabOnStop": True,
            "recordScreenshots": True,
            "blockAds": True,
            "monitorDownloads": True
        }
        
        # Send message to extension
        message = {
            "action": "startAutomation",
            "config": config
        }
        
        response = await self._send_extension_message(message)
        
        if response.get("success"):
            session_id = response["sessionId"]
            self.sessions[session_id] = {
                "config": config,
                "startTime": datetime.now(),
                "status": "running",
                "logs": [],
                "downloads": []
            }
            
            self.logger.info(f"Started automation session: {session_id}")
            return session_id
        else:
            raise Exception(f"Failed to start session: {response.get('error')}")
    
    async def navigate_to_url(self, session_id: str, url: str) -> bool:
        """Navigate to a specific URL"""
        if session_id not in self.sessions:
            raise Exception("Session not found")
        
        message = {
            "action": "navigateTo",
            "sessionId": session_id,
            "url": url
        }
        
        response = await self._send_extension_message(message)
        
        if response.get("success"):
            self.logger.info(f"Navigated to {url} in session {session_id}")
            return True
        else:
            self.logger.error(f"Navigation failed: {response.get('error')}")
            return False
    
    async def get_page_logs(self, session_id: str) -> List[Dict]:
        """Get detailed logs for a session"""
        if session_id not in self.sessions:
            raise Exception("Session not found")
        
        message = {
            "action": "getPageLogs",
            "sessionId": session_id
        }
        
        response = await self._send_extension_message(message)
        
        if response.get("success"):
            logs = response.get("logs", [])
            self.sessions[session_id]["logs"] = logs
            return logs
        else:
            raise Exception(f"Failed to get logs: {response.get('error')}")
    
    async def get_download_info(self, session_id: str) -> List[Dict]:
        """Get download information for a session"""
        if session_id not in self.sessions:
            raise Exception("Session not found")
        
        message = {
            "action": "getDownloadInfo",
            "sessionId": session_id
        }
        
        response = await self._send_extension_message(message)
        
        if response.get("success"):
            downloads = response.get("downloads", [])
            self.sessions[session_id]["downloads"] = downloads
            return downloads
        else:
            raise Exception(f"Failed to get download info: {response.get('error')}")
    
    async def stop_automation_session(self, session_id: str) -> bool:
        """Stop an automation session"""
        if session_id not in self.sessions:
            raise Exception("Session not found")
        
        message = {
            "action": "stopAutomation",
            "sessionId": session_id
        }
        
        response = await self._send_extension_message(message)
        
        if response.get("success"):
            self.sessions[session_id]["status"] = "stopped"
            self.logger.info(f"Stopped automation session: {session_id}")
            return True
        else:
            self.logger.error(f"Failed to stop session: {response.get('error')}")
            return False
    
    async def _send_extension_message(self, message: Dict) -> Dict:
        """Send message to Chrome extension"""
        try:
            # Use Chrome extension messaging API
            url = f"chrome-extension://{self.extension_id}/"
            
            # For now, simulate response (in real implementation, use Chrome DevTools Protocol)
            await asyncio.sleep(0.1)  # Simulate network delay
            
            # Mock response based on action
            if message["action"] == "startAutomation":
                return {
                    "success": True,
                    "sessionId": f"session_{uuid.uuid4().hex[:8]}"
                }
            elif message["action"] in ["navigateTo", "stopAutomation", "getPageLogs", "getDownloadInfo"]:
                return {"success": True}
            else:
                return {"success": False, "error": "Unknown action"}
                
        except Exception as e:
            self.logger.error(f"Failed to send message to extension: {e}")
            return {"success": False, "error": str(e)}
    
    def get_session_summary(self, session_id: str) -> Dict:
        """Get summary of a session"""
        if session_id not in self.sessions:
            raise Exception("Session not found")
        
        session = self.sessions[session_id]
        
        # Analyze downloads
        downloads = session.get("downloads", [])
        multi_file_downloads = [d for d in downloads if d.get("multiFileDetected")]
        total_downloads = len(downloads)
        
        # Analyze logs
        logs = session.get("logs", [])
        network_requests = [log for log in logs if log.get("type") == "network_request"]
        blocked_requests = [req for req in network_requests if req.get("blocked")]
        navigations = [log for log in logs if log.get("type") == "navigation"]
        
        return {
            "sessionId": session_id,
            "status": session["status"],
            "startTime": session["startTime"].isoformat(),
            "config": session["config"],
            "downloads": {
                "total": total_downloads,
                "multiFile": len(multi_file_downloads),
                "details": downloads
            },
            "activity": {
                "totalRequests": len(network_requests),
                "blockedRequests": len(blocked_requests),
                "navigations": len(navigations),
                "adsBlocked": len(blocked_requests)
            },
            "logs": logs
        }

class TestSuite:
    """Predefined test suites for common scenarios"""
    
    def __init__(self, controller: BrowserAutomationController):
        self.controller = controller
        
    async def run_security_test(self, urls: List[str]) -> Dict:
        """Run security test on multiple URLs"""
        results = {}
        
        for url in urls:
            try:
                # Start session
                session_id = await self.controller.start_automation_session({
                    "blockAds": True,
                    "monitorDownloads": True,
                    "recordScreenshots": True
                })
                
                # Navigate to URL
                success = await self.controller.navigate_to_url(session_id, url)
                
                if success:
                    # Wait for page to load
                    await asyncio.sleep(5)
                    
                    # Get logs and downloads
                    logs = await self.controller.get_page_logs(session_id)
                    downloads = await self.controller.get_download_info(session_id)
                    
                    results[url] = {
                        "success": True,
                        "sessionId": session_id,
                        "logs": logs,
                        "downloads": downloads,
                        "summary": self.controller.get_session_summary(session_id)
                    }
                else:
                    results[url] = {
                        "success": False,
                        "error": "Navigation failed"
                    }
                
                # Stop session
                await self.controller.stop_automation_session(session_id)
                
            except Exception as e:
                results[url] = {
                    "success": False,
                    "error": str(e)
                }
        
        return results
    
    async def run_download_test(self, test_url: str) -> Dict:
        """Test download monitoring capabilities"""
        session_id = await self.controller.start_automation_session({
            "monitorDownloads": True,
            "blockAds": False,
            "recordScreenshots": True
        })
        
        try:
            # Navigate to test URL
            await self.controller.navigate_to_url(session_id, test_url)
            
            # Wait for downloads
            await asyncio.sleep(10)
            
            # Get download info
            downloads = await self.controller.get_download_info(session_id)
            logs = await self.controller.get_page_logs(session_id)
            
            # Analyze multi-file downloads
            multi_files = [d for d in downloads if d.get("multiFileDetected")]
            
            return {
                "success": True,
                "sessionId": session_id,
                "testUrl": test_url,
                "downloads": downloads,
                "multiFileDownloads": multi_files,
                "totalDownloads": len(downloads),
                "logs": logs,
                "summary": self.controller.get_session_summary(session_id)
            }
            
        finally:
            await self.controller.stop_automation_session(session_id)
    
    async def run_ad_blocking_test(self, url: str) -> Dict:
        """Test ad blocking effectiveness"""
        session_id = await self.controller.start_automation_session({
            "blockAds": True,
            "monitorDownloads": False,
            "recordScreenshots": True
        })
        
        try:
            # Navigate to URL
            await self.controller.navigate_to_url(session_id, url)
            
            # Wait for page to load
            await asyncio.sleep(5)
            
            # Get logs
            logs = await self.controller.get_page_logs(session_id)
            
            # Analyze blocked requests
            network_requests = [log for log in logs if log.get("type") == "network_request"]
            blocked_requests = [req for req in network_requests if req.get("blocked")]
            
            return {
                "success": True,
                "sessionId": session_id,
                "testUrl": url,
                "totalRequests": len(network_requests),
                "blockedRequests": len(blocked_requests),
                "blockingRate": len(blocked_requests) / len(network_requests) if network_requests else 0,
                "logs": logs,
                "summary": self.controller.get_session_summary(session_id)
            }
            
        finally:
            await self.controller.stop_automation_session(session_id)

# CLI Interface
import asyncio
import argparse

async def main():
    parser = argparse.ArgumentParser(description="Browser Automation Test Controller")
    parser.add_argument("--extension-id", help="Chrome extension ID")
    parser.add_argument("--test", choices=["security", "download", "adblock"], help="Test type to run")
    parser.add_argument("--urls", nargs="+", help="URLs to test")
    parser.add_argument("--url", help="Single URL to test")
    
    args = parser.parse_args()
    
    controller = BrowserAutomationController()
    
    if args.extension_id:
        controller.connect_to_extension(args.extension_id)
    
    test_suite = TestSuite(controller)
    
    if args.test == "security" and args.urls:
        results = await test_suite.run_security_test(args.urls)
        print(json.dumps(results, indent=2))
        
    elif args.test == "download" and args.url:
        result = await test_suite.run_download_test(args.url)
        print(json.dumps(result, indent=2))
        
    elif args.test == "adblock" and args.url:
        result = await test_suite.run_ad_blocking_test(args.url)
        print(json.dumps(result, indent=2))
        
    else:
        print("Please specify test type and appropriate arguments")

if __name__ == "__main__":
    asyncio.run(main())
