# vt_analyzer/utils.py

import re
import requests
import time
import hashlib
from django.conf import settings
from django.core.files.uploadedfile import UploadedFile

# ==================== INPUT TYPE DETECTION ====================

def detect_input_type(input_value):
    """Detect if input is URL, IP, hash, or domain"""
    # IP pattern (basic IPv4)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Hash patterns
    md5_pattern = r'^[a-fA-F0-9]{32}$'
    sha1_pattern = r'^[a-fA-F0-9]{40}$'
    sha256_pattern = r'^[a-fA-F0-9]{64}$'
    # URL pattern
    url_pattern = r'^https?://'
    
    if re.match(url_pattern, input_value):
        return 'url'
    elif re.match(ip_pattern, input_value):
        return 'ip'
    elif re.match(md5_pattern, input_value) or re.match(sha1_pattern, input_value) or re.match(sha256_pattern, input_value):
        return 'hash'
    else:
        return 'domain'


# ==================== VIRUSTOTAL API FUNCTIONS ====================

def get_vt_headers():
    """Get VirusTotal API headers"""
    vt_api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
    if not vt_api_key:
        raise ValueError("VIRUSTOTAL_API_KEY not configured in settings")
    
    return {
        'x-apikey': vt_api_key,
        'Accept': 'application/json'
    }


def vt_scan_file(file):
    """
    Scan file with VirusTotal
    
    Args:
        file: Django UploadedFile object
    
    Returns:
        dict: VirusTotal API response or error dict
    """
    try:
        vt_api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', None)
        if not vt_api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        url = 'https://www.virustotal.com/api/v3/files'
        
        # Read file content
        file.seek(0)
        files = {'file': (file.name, file.read())}
        headers = {'x-apikey': vt_api_key}
        
        # Upload file
        response = requests.post(url, headers=headers, files=files, timeout=60)
        
        if response.status_code == 200:
            result = response.json()
            file_id = result.get('data', {}).get('id')
            
            # Wait and get analysis results
            time.sleep(15)  # Wait for analysis
            
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
            analysis_response = requests.get(analysis_url, headers=headers, timeout=30)
            
            if analysis_response.status_code == 200:
                return analysis_response.json()
            else:
                return {'error': f'Failed to get analysis: {analysis_response.status_code}'}
        else:
            return {'error': f'Upload failed: {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}


def vt_scan_url(url):
    """
    Scan URL with VirusTotal
    
    Args:
        url: URL string to scan
    
    Returns:
        dict: VirusTotal API response or error dict
    """
    try:
        headers = get_vt_headers()
        
        # Submit URL for scanning
        vt_url = 'https://www.virustotal.com/api/v3/urls'
        data = {'url': url}
        
        response = requests.post(vt_url, headers=headers, data=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            analysis_id = result.get('data', {}).get('id')
            
            # Get analysis results
            time.sleep(10)  # Wait for analysis
            
            analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
            analysis_response = requests.get(analysis_url, headers=headers, timeout=30)
            
            if analysis_response.status_code == 200:
                return analysis_response.json()
            else:
                # Try to get URL report directly
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                report_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
                report_response = requests.get(report_url, headers=headers, timeout=30)
                
                if report_response.status_code == 200:
                    return report_response.json()
                else:
                    return {'error': f'Failed to get analysis: {report_response.status_code}'}
        else:
            return {'error': f'Scan submission failed: {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}


def vt_scan_ip(ip):
    """
    Scan IP address with VirusTotal
    
    Args:
        ip: IP address string
    
    Returns:
        dict: VirusTotal API response or error dict
    """
    try:
        headers = get_vt_headers()
        
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {'error': 'IP address not found in VirusTotal database'}
        else:
            return {'error': f'API request failed: {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}


def vt_scan_hash(hash_value):
    """
    Scan file hash with VirusTotal
    
    Args:
        hash_value: File hash (MD5, SHA1, or SHA256)
    
    Returns:
        dict: VirusTotal API response or error dict
    """
    try:
        headers = get_vt_headers()
        
        url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {'error': 'Hash not found in VirusTotal database'}
        else:
            return {'error': f'API request failed: {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}


# ==================== ALIENVAULT OTX API FUNCTIONS ====================

def get_otx_headers():
    """Get AlienVault OTX API headers"""
    otx_api_key = getattr(settings, 'OTX_API_KEY', None)
    if not otx_api_key:
        raise ValueError("OTX_API_KEY not configured in settings")
    
    return {
        'X-OTX-API-KEY': otx_api_key,
        'Accept': 'application/json'
    }


def otx_scan_url(url):
    """
    Scan URL with AlienVault OTX
    
    Args:
        url: URL string to scan
    
    Returns:
        dict: OTX API response or error dict
    """
    try:
        headers = get_otx_headers()
        
        # Extract domain from URL
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        otx_url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
        response = requests.get(otx_url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            
            # Get additional reputation data
            reputation_url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/reputation'
            rep_response = requests.get(reputation_url, headers=headers, timeout=30)
            
            if rep_response.status_code == 200:
                result['reputation'] = rep_response.json()
            
            return result
        else:
            return {'error': f'OTX API request failed: {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}


def otx_scan_ip(ip):
    """
    Scan IP address with AlienVault OTX
    
    Args:
        ip: IP address string
    
    Returns:
        dict: OTX API response or error dict
    """
    try:
        headers = get_otx_headers()
        
        # Get general info
        url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general'
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            
            # Get reputation data
            reputation_url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation'
            rep_response = requests.get(reputation_url, headers=headers, timeout=30)
            
            if rep_response.status_code == 200:
                result['reputation'] = rep_response.json()
            
            # Get malware data
            malware_url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/malware'
            mal_response = requests.get(malware_url, headers=headers, timeout=30)
            
            if mal_response.status_code == 200:
                result['malware'] = mal_response.json()
            
            return result
        else:
            return {'error': f'OTX API request failed: {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}


def otx_scan_hash(hash_value):
    """
    Scan file hash with AlienVault OTX
    
    Args:
        hash_value: File hash (MD5, SHA1, or SHA256)
    
    Returns:
        dict: OTX API response or error dict
    """
    try:
        headers = get_otx_headers()
        
        # Determine hash type
        hash_type = 'file'
        if len(hash_value) == 32:
            hash_type = 'file'  # MD5
        elif len(hash_value) == 40:
            hash_type = 'file'  # SHA1
        elif len(hash_value) == 64:
            hash_type = 'file'  # SHA256
        
        url = f'https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/general'
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            
            # Get analysis data
            analysis_url = f'https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/analysis'
            analysis_response = requests.get(analysis_url, headers=headers, timeout=30)
            
            if analysis_response.status_code == 200:
                result['analysis'] = analysis_response.json()
            
            return result
        else:
            return {'error': f'OTX API request failed: {response.status_code}'}
    
    except Exception as e:
        return {'error': str(e)}


# ==================== IP GEOLOCATION ====================

def get_ip_info(ip):
    """
    Get IP geolocation and ASN information
    Uses ipapi.co free API (no key required for basic usage)
    
    Args:
        ip: IP address string
    
    Returns:
        dict: IP information or None on error
    """
    try:
        # Using ipapi.co (free tier: 1000 requests/day)
        url = f'https://ipapi.co/{ip}/json/'
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': data.get('ip'),
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'org': data.get('org'),
                'asn': data.get('asn'),
                'timezone': data.get('timezone'),
                'postal': data.get('postal'),
            }
        else:
            # Fallback to ip-api.com (free, no key required)
            fallback_url = f'http://ip-api.com/json/{ip}'
            fallback_response = requests.get(fallback_url, timeout=10)
            
            if fallback_response.status_code == 200:
                data = fallback_response.json()
                if data.get('status') == 'success':
                    return {
                        'ip': data.get('query'),
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'org': data.get('isp'),
                        'asn': data.get('as'),
                        'timezone': data.get('timezone'),
                        'postal': data.get('zip'),
                    }
            
            return None
    
    except Exception as e:
        print(f"IP info error: {str(e)}")
        return None


# ==================== HELPER FUNCTIONS ====================

def calculate_file_hash(file, algorithm='sha256'):
    """
    Calculate hash of uploaded file
    
    Args:
        file: Django UploadedFile object
        algorithm: Hash algorithm (md5, sha1, sha256)
    
    Returns:
        str: Hex digest of file hash
    """
    file.seek(0)
    
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    else:
        hasher = hashlib.sha256()
    
    for chunk in file.chunks():
        hasher.update(chunk)
    
    file.seek(0)
    return hasher.hexdigest()


def is_valid_ipv4(ip):
    """Validate IPv4 address"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False


def is_private_ip(ip):
    """Check if IP is private/internal"""
    private_ranges = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^169\.254\.',
    ]
    return any(re.match(pattern, ip) for pattern in private_ranges)