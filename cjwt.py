#!/usr/bin/env python3

import json
import re
import jwt
import sys
import argparse
import os
from colorama import init, Fore, Style
import pyperclip
import base64
from datetime import datetime, timezone, timedelta

# Initialize colorama
init()

# Global variable to control color output
USE_COLORS = True

def set_color_mode(use_colors):
    """Set whether to use colors in output."""
    global USE_COLORS
    USE_COLORS = use_colors

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
    
    if not USE_COLORS:
        return formatted
        
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
    if USE_COLORS:
        print(f"\n{color}\033[1m{title}\033[0m{Style.RESET_ALL}")
    else:
        print(f"\n{title}")
    print(content)

def print_colored_json(data):
    """Print JSON data with colors."""
    if isinstance(data, dict) and "error" in data:
        if USE_COLORS:
            print(f"{Fore.RED}Error: {data['error']}{Style.RESET_ALL}")
        else:
            print(f"Error: {data['error']}")
        return

    # Print timestamp information
    payload = data['payload']
    if 'exp' in payload and 'iat' in payload:
        # Get the formatted values first to calculate max length
        issued_at = format_timestamp(payload['iat'])
        expires_at_val = format_timestamp(payload['exp'])
        time_remaining_val = get_time_remaining(payload['exp'])
        
        # Add not before time if it exists
        not_before = format_timestamp(payload['nbf']) if 'nbf' in payload else None
        
        # Calculate the maximum length needed
        max_len = max(
            len(issued_at),
            len(expires_at_val),
            len(time_remaining_val),
            len(not_before) if not_before else 0
        ) + 25  # Add padding for labels and borders
        
        # Create a formatted timestamp section
        timestamp_info = []
        timestamp_info.append(f"┌{'─' * max_len}┐")
        timestamp_info.append(f"│ {'Issued at:':<15} {issued_at:<{max_len-18}} │")
        
        if not_before:
            timestamp_info.append(f"│ {'Not before:':<15} {not_before:<{max_len-18}} │")
        
        # Check if token is expired
        now = datetime.now(timezone.utc).timestamp()
        is_expired = payload['exp'] < now
        
        if USE_COLORS:
            exp_color = Fore.LIGHTRED_EX if is_expired else Fore.GREEN
            expires_at_str = f"{exp_color}{expires_at_val:<{max_len-18}}{Style.RESET_ALL}"
            time_remaining_str = f"{exp_color}{time_remaining_val:<{max_len-18}}{Style.RESET_ALL}"
        else:
            expires_at_str = f"{expires_at_val:<{max_len-18}}"
            time_remaining_str = f"{time_remaining_val:<{max_len-18}}"

        timestamp_info.append(f"│ {'Expires at:':<15} {expires_at_str} │")
        timestamp_info.append(f"│ {'Time remaining:':<15} {time_remaining_str} │")
        timestamp_info.append(f"└{'─' * max_len}┘")
        
        print('\n'.join(timestamp_info))

    # Print header
    print_section("Header", colorize_json(data['header']))

    # Print payload
    print_section("Payload", colorize_json(data['payload']))

    # Print signature
    signature_content = data['signature']
    if USE_COLORS:
        signature_content = f"{Fore.CYAN}{data['signature']}{Style.RESET_ALL}"
    print_section("Signature", signature_content)

def get_token_from_source(args):
    """Get token from specified source (stdin, clipboard, file, or directly specified)."""
    # Check if input is piped and no explicit token or file is given
    if not sys.stdin.isatty() and args.token is None and args.file is None:
        # Read from stdin if it's being piped
        for line in sys.stdin:
            line = line.strip()
            if is_jwt(line):
                return line
        print(f"{Fore.RED}No JWT tokens found in stdin input.{Style.RESET_ALL}")
        sys.exit(1)
    if hasattr(args, 'token') and args.token:
        return args.token
    elif hasattr(args, 'file') and args.file:
        try:
            with open(args.file, 'r') as f:
                return f.read().strip()
        except Exception as e:
            print(f"{Fore.RED}Error reading file: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
    else:
        # Default to clipboard
        content = pyperclip.paste()
        if not content:
            print(f"{Fore.RED}No content found in clipboard.{Style.RESET_ALL}")
            sys.exit(1)
        # Try to find a JWT in the content
        for line in content.splitlines():
            line = line.strip()
            if is_jwt(line):
                return line
        print(f"{Fore.RED}No JWT tokens found in the clipboard content.{Style.RESET_ALL}")
        sys.exit(1)

def read_key_file(file_path):
    """Read key from file."""
    try:
        with open(file_path, 'r') as f:
            return f.read().strip()
    except Exception as e:
        print(f"{Fore.RED}Error reading key file: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def parse_claims(claims_str):
    """Parse claims JSON string."""
    try:
        return json.loads(claims_str)
    except Exception as e:
        print(f"{Fore.RED}Error parsing claims JSON: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def cmd_decode(args):
    """Handle decode command."""
    token = get_token_from_source(args)
    if token:
        decoded = decode_jwt(token)
        print_colored_json(decoded)

def cmd_create(args):
    """Handle create command."""
    claims = parse_claims(args.claims)
    
    # Add expiration if specified
    if args.exp:
        claims['exp'] = datetime.now(timezone.utc).timestamp() + args.exp
    
    # Add issued at
    claims['iat'] = datetime.now(timezone.utc).timestamp()
    
    # Determine the algorithm and key to use
    algorithm = args.alg if hasattr(args, 'alg') and args.alg else 'HS256'
    
    try:
        # Handle different key types
        if hasattr(args, 'private_key') and args.private_key:
            key = read_key_file(args.private_key)
        elif hasattr(args, 'secret') and args.secret:
            key = args.secret
        elif hasattr(args, 'jwk') and args.jwk:
            key = read_key_file(args.jwk)
            key = json.loads(key)  # Parse JWK
        elif hasattr(args, 'pem') and args.pem:
            key = read_key_file(args.pem)
        else:
            print(f"{Fore.RED}Error: No key or secret provided{Style.RESET_ALL}")
            sys.exit(1)
            
        token = jwt.encode(claims, key, algorithm=algorithm)
        print(token)
        
    except Exception as e:
        print(f"{Fore.RED}Error creating JWT: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def cmd_validate(args):
    """Handle validate command."""
    token = get_token_from_source(args)
    
    try:
        # Determine the key to use
        if hasattr(args, 'public_key') and args.public_key:
            key = read_key_file(args.public_key)
        elif hasattr(args, 'secret') and args.secret:
            key = args.secret
        else:
            print(f"{Fore.RED}Error: No key or secret provided{Style.RESET_ALL}")
            sys.exit(1)
        
        # Decode without verification first to determine algorithm
        decoded_header = jwt.get_unverified_header(token)
        algorithm = decoded_header.get('alg', 'HS256')
        
        # Now decode with verification
        decoded = jwt.decode(token, key, algorithms=[algorithm])
        print(f"{Fore.GREEN}✓ JWT is valid!{Style.RESET_ALL}")
        print_colored_json({"header": decoded_header, "payload": decoded, "signature": token.split('.')[2], "raw_token": token})
        
    except jwt.ExpiredSignatureError:
        print(f"{Fore.RED}✗ JWT has expired{Style.RESET_ALL}")
        sys.exit(1)
    except jwt.InvalidTokenError as e:
        print(f"{Fore.RED}✗ Invalid JWT: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def cmd_sign(args):
    """Handle sign command."""
    claims = parse_claims(args.claims)
    algorithm = args.alg if hasattr(args, 'alg') and args.alg else 'HS256'
    
    try:
        # Handle different key types
        if hasattr(args, 'private_key') and args.private_key:
            key = read_key_file(args.private_key)
        elif hasattr(args, 'secret') and args.secret:
            key = args.secret
        else:
            print(f"{Fore.RED}Error: No key or secret provided{Style.RESET_ALL}")
            sys.exit(1)
            
        token = jwt.encode(claims, key, algorithm=algorithm)
        print(token)
        
    except Exception as e:
        print(f"{Fore.RED}Error signing JWT: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def cmd_verify(args):
    """Handle verify command."""
    token = get_token_from_source(args)
    required_claims = json.loads(args.required_claims) if args.required_claims else []
    
    try:
        # Determine the key to use
        if hasattr(args, 'public_key') and args.public_key:
            key = read_key_file(args.public_key)
        elif hasattr(args, 'secret') and args.secret:
            key = args.secret
        else:
            print(f"{Fore.RED}Error: No key or secret provided{Style.RESET_ALL}")
            sys.exit(1)
        
        # Decode without verification first to determine algorithm
        decoded_header = jwt.get_unverified_header(token)
        algorithm = decoded_header.get('alg', 'HS256')
        
        # Now decode with verification
        decoded = jwt.decode(token, key, algorithms=[algorithm])
        
        # Check for required claims
        missing_claims = []
        for claim in required_claims:
            if claim not in decoded:
                missing_claims.append(claim)
        
        if missing_claims:
            print(f"{Fore.RED}✗ JWT is missing required claims: {', '.join(missing_claims)}{Style.RESET_ALL}")
            sys.exit(1)
        else:
            print(f"{Fore.GREEN}✓ JWT is valid and contains all required claims!{Style.RESET_ALL}")
            print_colored_json({"header": decoded_header, "payload": decoded, "signature": token.split('.')[2], "raw_token": token})
        
    except jwt.ExpiredSignatureError:
        print(f"{Fore.RED}✗ JWT has expired{Style.RESET_ALL}")
        sys.exit(1)
    except jwt.InvalidTokenError as e:
        print(f"{Fore.RED}✗ Invalid JWT: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def cmd_header(args):
    """Handle header command."""
    token = get_token_from_source(args)
    decoded = decode_jwt(token)
    
    if "error" in decoded:
        print(f"{Fore.RED}Error: {decoded['error']}{Style.RESET_ALL}")
        sys.exit(1)
    
    print_section("Header", colorize_json(decoded['header']))

def cmd_extract(args):
    """Handle extract command."""
    token = get_token_from_source(args)
    claims_to_extract = json.loads(args.claims) if args.claims else []
    
    decoded = decode_jwt(token)
    if "error" in decoded:
        print(f"{Fore.RED}Error: {decoded['error']}{Style.RESET_ALL}")
        sys.exit(1)
    
    if not claims_to_extract:
        # If no specific claims are requested, print all
        print_section("Payload", colorize_json(decoded['payload']))
    else:
        # Extract only the requested claims
        extracted = {}
        for claim in claims_to_extract:
            if claim in decoded['payload']:
                extracted[claim] = decoded['payload'][claim]
            else:
                print(f"{Fore.YELLOW}Warning: Claim '{claim}' not found in payload{Style.RESET_ALL}")
        
        print_section("Extracted Claims", colorize_json(extracted))

def cmd_check_exp(args):
    """Handle check-exp command."""
    token = get_token_from_source(args)
    decoded = decode_jwt(token)
    
    if "error" in decoded:
        print(f"{Fore.RED}Error: {decoded['error']}{Style.RESET_ALL}")
        sys.exit(1)
    
    if 'exp' not in decoded['payload']:
        print(f"{Fore.YELLOW}JWT does not have an expiration claim!{Style.RESET_ALL}")
        sys.exit(0)
    
    now = datetime.now(timezone.utc).timestamp()
    exp_time = decoded['payload']['exp']
    
    if exp_time < now:
        time_ago = get_time_remaining(exp_time)
        print(f"{Fore.RED}✗ JWT has expired ({time_ago}){Style.RESET_ALL}")
        sys.exit(1)
    else:
        time_left = get_time_remaining(exp_time)
        print(f"{Fore.GREEN}✓ JWT is not expired ({time_left} remaining){Style.RESET_ALL}")

def cmd_add_exp(args):
    """Handle add-exp command."""
    token = get_token_from_source(args)
    decoded = decode_jwt(token)
    
    if "error" in decoded:
        print(f"{Fore.RED}Error: {decoded['error']}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Add or update expiration
    payload = decoded['payload']
    payload['exp'] = datetime.now(timezone.utc).timestamp() + args.exp
    
    # We need the key to re-sign
    try:
        # Determine the key to use
        if hasattr(args, 'secret') and args.secret:
            key = args.secret
        elif hasattr(args, 'private_key') and args.private_key:
            key = read_key_file(args.private_key)
        else:
            print(f"{Fore.RED}Error: No key or secret provided{Style.RESET_ALL}")
            sys.exit(1)
        
        # Get the algorithm from the header
        algorithm = decoded['header'].get('alg', 'HS256')
        
        # Create a new token with the updated payload
        new_token = jwt.encode(payload, key, algorithm=algorithm, headers=decoded['header'])
        print(new_token)
        
    except Exception as e:
        print(f"{Fore.RED}Error adding expiration to JWT: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

def cmd_format(args):
    """Handle format command."""
    token = get_token_from_source(args)
    decoded = decode_jwt(token)
    
    if "error" in decoded:
        print(f"{Fore.RED}Error: {decoded['error']}{Style.RESET_ALL}")
        sys.exit(1)
    
    if args.format == 'compact':
        # Already in compact format
        print(token)
    elif args.format == 'json':
        # Format as JSON
        json_output = {
            "header": decoded['header'],
            "payload": decoded['payload'],
            "signature": decoded['signature']
        }
        print(json.dumps(json_output, indent=2))
    else:
        print(f"{Fore.RED}Unknown format: {args.format}{Style.RESET_ALL}")
        sys.exit(1)

def cmd_batch(args):
    """Handle batch processing command."""
    try:
        with open(args.file, 'r') as f:
            tokens = [line.strip() for line in f if line.strip() and is_jwt(line.strip())]
    except Exception as e:
        print(f"{Fore.RED}Error reading file: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    
    if not tokens:
        print(f"{Fore.RED}No valid JWTs found in file!{Style.RESET_ALL}")
        sys.exit(1)
    
    results = []
    
    for i, token in enumerate(tokens):
        print(f"\n{Fore.CYAN}Processing token {i+1}/{len(tokens)}{Style.RESET_ALL}")
        
        if args.action == 'decode':
            decoded = decode_jwt(token)
            print_colored_json(decoded)
            results.append({"action": "decode", "success": "error" not in decoded})
            
        elif args.action == 'validate':
            try:
                # Determine the key to use
                if hasattr(args, 'public_key') and args.public_key:
                    key = read_key_file(args.public_key)
                elif hasattr(args, 'secret') and args.secret:
                    key = args.secret
                else:
                    print(f"{Fore.RED}Error: No key or secret provided{Style.RESET_ALL}")
                    sys.exit(1)
                
                # Decode without verification first to determine algorithm
                decoded_header = jwt.get_unverified_header(token)
                algorithm = decoded_header.get('alg', 'HS256')
                
                # Now decode with verification
                decoded = jwt.decode(token, key, algorithms=[algorithm])
                print(f"{Fore.GREEN}✓ Token {i+1} is valid!{Style.RESET_ALL}")
                results.append({"action": "validate", "success": True})
                
            except jwt.ExpiredSignatureError:
                print(f"{Fore.RED}✗ Token {i+1} has expired{Style.RESET_ALL}")
                results.append({"action": "validate", "success": False, "reason": "expired"})
                
            except jwt.InvalidTokenError as e:
                print(f"{Fore.RED}✗ Token {i+1} is invalid: {str(e)}{Style.RESET_ALL}")
                results.append({"action": "validate", "success": False, "reason": str(e)})
    
    # Print summary
    success_count = sum(1 for r in results if r["success"])
    print(f"\n{Fore.CYAN}Batch Summary:{Style.RESET_ALL}")
    print(f"Processed {len(tokens)} tokens: {success_count} successful, {len(tokens) - success_count} failed")

def main():
    parser = argparse.ArgumentParser(description='JWT CLI Tool')
    parser.add_argument('--no-colors', action='store_true', help='Disable colored output (useful for piping)')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Decode a JWT token')
    decode_parser.add_argument('-t', '--token', help='JWT token to decode')
    decode_parser.add_argument('-f', '--file', help='File containing JWT token')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new JWT token')
    create_parser.add_argument('-c', '--claims', required=True, help='JSON string of claims')
    create_parser.add_argument('-e', '--exp', type=int, help='Expiration time in seconds from now')
    create_parser.add_argument('-a', '--alg', help='Signing algorithm (default: HS256)')
    create_parser.add_argument('-k', '--secret', help='Secret key for signing')
    create_parser.add_argument('-p', '--private-key', help='Path to private key file')
    create_parser.add_argument('-j', '--jwk', help='Path to JWK file')
    
    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate a JWT token")
    validate_parser.add_argument("--token", help="JWT token to validate")
    validate_parser.add_argument("--file", help="File containing JWT token")
    validate_parser.add_argument("--secret", help="Secret key for validation")
    validate_parser.add_argument("--public-key", help="Path to public key file")
    
    # Sign command
    sign_parser = subparsers.add_parser("sign", help="Sign a JWT token")
    sign_parser.add_argument("--claims", required=True, help="JSON string of claims to include")
    sign_parser.add_argument("--secret", help="Secret key for signing")
    sign_parser.add_argument("--private-key", help="Path to private key file")
    sign_parser.add_argument("--alg", help="Algorithm to use (default: HS256)")
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a JWT token")
    verify_parser.add_argument("--token", help="JWT token to verify")
    verify_parser.add_argument("--file", help="File containing JWT token")
    verify_parser.add_argument("--secret", help="Secret key for verification")
    verify_parser.add_argument("--public-key", help="Path to public key file")
    verify_parser.add_argument("--required-claims", help="JSON array of required claims")
    
    # Header command
    header_parser = subparsers.add_parser("header", help="Show JWT header")
    header_parser.add_argument("--token", help="JWT token")
    header_parser.add_argument("--file", help="File containing JWT token")
    
    # Extract command
    extract_parser = subparsers.add_parser("extract", help="Extract claims from JWT payload")
    extract_parser.add_argument("--token", help="JWT token")
    extract_parser.add_argument("--file", help="File containing JWT token")
    extract_parser.add_argument("--claims", help="JSON array of claims to extract")
    
    # Check expiration command
    check_exp_parser = subparsers.add_parser("check-exp", help="Check if JWT is expired")
    check_exp_parser.add_argument("--token", help="JWT token")
    check_exp_parser.add_argument("--file", help="File containing JWT token")
    
    # Add expiration command
    add_exp_parser = subparsers.add_parser("add-exp", help="Add expiration to JWT")
    add_exp_parser.add_argument("--token", help="JWT token")
    add_exp_parser.add_argument("--file", help="File containing JWT token")
    add_exp_parser.add_argument("--exp", type=int, required=True, help="Expiration time in seconds")
    add_exp_parser.add_argument("--secret", help="Secret key for re-signing")
    add_exp_parser.add_argument("--private-key", help="Path to private key file")
    
    # Format command
    format_parser = subparsers.add_parser("format", help="Convert JWT to different format")
    format_parser.add_argument("--token", help="JWT token")
    format_parser.add_argument("--file", help="File containing JWT token")
    format_parser.add_argument("--format", required=True, choices=["compact", "json"], help="Output format")
    
    # Batch processing command
    batch_parser = subparsers.add_parser("batch", help="Process multiple JWTs")
    batch_parser.add_argument("--file", required=True, help="File containing JWT tokens (one per line)")
    batch_parser.add_argument("--action", required=True, choices=["decode", "validate"], help="Action to perform")
    batch_parser.add_argument("--secret", help="Secret key for validation")
    batch_parser.add_argument("--public-key", help="Path to public key file")
    
    args = parser.parse_args()
    
    # Set color mode based on arguments and whether stdout is a terminal
    use_colors = not args.no_colors and sys.stdout.isatty()
    set_color_mode(use_colors)
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
        
    # Map commands to their handler functions
    commands = {
        'decode': cmd_decode,
        'create': cmd_create,
        'validate': cmd_validate,
        'sign': cmd_sign,
        'verify': cmd_verify,
        'header': cmd_header,
        'extract': cmd_extract,
        'check-exp': cmd_check_exp,
        'add-exp': cmd_add_exp,
        'format': cmd_format,
        'batch': cmd_batch
    }
    
    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main() 
