#!/usr/bin/env python3

import json
import re
import jwt
from colorama import init, Fore, Style
import pyperclip
import base64
from datetime import datetime, timezone

# Initialize colorama
init()

def is_jwt(token):
    """Check if a string matches JWT format."""
    jwt_pattern = r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$'
    return bool(re.match(jwt_pattern, token))

def decode_jwt(token):
    """Decode JWT token and return all parts."""
    try:
        # Split the token into parts
        parts = token.split('.')
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}

        # Decode header
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode('utf-8'))
        
        # Decode payload
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode('utf-8'))
        
        # Get signature
        signature = parts[2]

        return {
            "header": header,
            "payload": payload,
            "signature": signature,
            "raw_token": token
        }
    except Exception as e:
        return {"error": str(e)}

def format_timestamp(timestamp):
    """Convert Unix timestamp to human-readable format."""
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')

def get_time_remaining(exp_timestamp):
    """Calculate time remaining until expiration."""
    now = datetime.now(timezone.utc)
    exp = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
    diff = exp - now
    
    if diff.total_seconds() < 0:
        # Handle expired tokens
        abs_diff = abs(diff)
        days = abs_diff.days
        hours = abs_diff.seconds // 3600
        minutes = (abs_diff.seconds % 3600) // 60
        seconds = abs_diff.seconds % 60
        
        if days > 0:
            return f"Expired {days} days" + (f", {hours} hours" if hours > 0 else "") + " ago"
        elif hours > 0:
            return f"Expired {hours} hours" + (f", {minutes} minutes" if minutes > 0 else "") + " ago"
        elif minutes > 0:
            return f"Expired {minutes} minutes" + (f", {seconds} seconds" if seconds > 0 else "") + " ago"
        else:
            return f"Expired {seconds} seconds ago"
    
    # Handle non-expired tokens
    days = diff.days
    hours = diff.seconds // 3600
    minutes = (diff.seconds % 3600) // 60
    seconds = diff.seconds % 60
    
    if days > 0:
        parts = [f"{days} days"]
        if hours > 0:
            parts.append(f"{hours} hours")
        if minutes > 0:
            parts.append(f"{minutes} minutes")
        return ", ".join(parts)
    elif hours > 0:
        parts = [f"{hours} hours"]
        if minutes > 0:
            parts.append(f"{minutes} minutes")
        return ", ".join(parts)
    elif minutes > 0:
        parts = [f"{minutes} minutes"]
        if seconds > 0:
            parts.append(f"{seconds} seconds")
        return ", ".join(parts)
    else:
        return f"{seconds} seconds"

def colorize_json(json_str):
    """Colorize a JSON string with proper color formatting."""
    # First format the JSON with proper indentation
    formatted = json.dumps(json_str, indent=2)
    
    # Apply colors to different parts
    colored = formatted
    # Color the keys
    colored = re.sub(r'(\s*)"([^"]+)":', r'\1' + Fore.YELLOW + r'"\2"' + Style.RESET_ALL + ':', colored)
    # Color the string values
    colored = re.sub(r':\s*"([^"]*)"', ': ' + Fore.CYAN + r'"\1"' + Style.RESET_ALL, colored)
    # Color the numbers
    colored = re.sub(r':\s*(\d+)', ': ' + Fore.MAGENTA + r'\1' + Style.RESET_ALL, colored)
    # Color the boolean values
    colored = re.sub(r':\s*(true|false)', ': ' + Fore.MAGENTA + r'\1' + Style.RESET_ALL, colored)
    
    return colored

def print_section(title, content, color=Fore.YELLOW):
    """Print a section with a title and content."""
    print(f"\n{color}\033[1m{title}\033[0m{Style.RESET_ALL}")
    print(content)

def print_colored_json(data):
    """Print JSON data with colors."""
    if isinstance(data, dict) and "error" in data:
        print(f"{Fore.RED}Error: {data['error']}{Style.RESET_ALL}")
        return

    # Print timestamp information
    payload = data['payload']
    if 'exp' in payload and 'iat' in payload:
        # Get the formatted values first to calculate max length
        issued_at = format_timestamp(payload['iat'])
        expires_at = format_timestamp(payload['exp'])
        time_remaining = get_time_remaining(payload['exp'])
        
        # Add not before time if it exists
        not_before = format_timestamp(payload['nbf']) if 'nbf' in payload else None
        
        # Calculate the maximum length needed
        max_length = max(
            len(issued_at),
            len(expires_at),
            len(time_remaining),
            len(not_before) if not_before else 0
        ) + 25  # Add padding for labels and borders
        
        # Create a formatted timestamp section
        timestamp_info = []
        timestamp_info.append(f"┌{'─' * max_length}┐")
        timestamp_info.append(f"│ {'Issued at:':<15} {issued_at:<{max_length-18}} │")
        
        if not_before:
            timestamp_info.append(f"│ {'Not before:':<15} {not_before:<{max_length-18}} │")
        
        # Check if token is expired
        now = datetime.now(timezone.utc).timestamp()
        is_expired = payload['exp'] < now
        exp_color = Fore.LIGHTRED_EX if is_expired else Fore.GREEN
        
        timestamp_info.append(f"│ {'Expires at:':<15} {exp_color}{expires_at:<{max_length-18}}{Style.RESET_ALL} │")
        timestamp_info.append(f"│ {'Time remaining:':<15} {exp_color}{time_remaining:<{max_length-18}}{Style.RESET_ALL} │")
        timestamp_info.append(f"└{'─' * max_length}┘")
        
        print('\n'.join(timestamp_info))

    # Print header
    print_section("Header", colorize_json(data['header']))

    # Print payload
    print_section("Payload", colorize_json(data['payload']))

    # Print signature
    print_section("Signature", f"{Fore.CYAN}{data['signature']}{Style.RESET_ALL}")

def main():
    try:
        # Get content from clipboard
        content = pyperclip.paste()
        
        if not content:
            print(f"{Fore.RED}No content found in clipboard.{Style.RESET_ALL}")
            return

        # Split content into lines and check each line
        lines = content.splitlines()
        jwt_found = False

        for line in lines:
            line = line.strip()
            if is_jwt(line):
                jwt_found = True
                decoded = decode_jwt(line)
                print_colored_json(decoded)

        if not jwt_found:
            print(f"{Fore.RED}No JWT tokens found in the clipboard content.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 
