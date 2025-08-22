from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from flask import Flask, request, jsonify
import requests
import random
import uid_generator_pb2
from zitado_ujjaiwal_pb2 import Users
from secret import key, iv
import json
import time

app = Flask(__name__)

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def create_protobuf(ujjaiwal_, garena):
    message = uid_generator_pb2.uid_generator()
    message.ujjaiwal_ = ujjaiwal_
    message.garena = garena
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = Users()
    users.ParseFromString(byte_data)
    return users

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def get_credentials(region):
    region = region.upper()
    if region == "IND":
        return "3943735419", "D00171F210873075DE973C7E40936D8A56A9E5FD4DFA7F2A2CE1ED07759F9DB6"
    elif region in ["NA", "BR", "SAC", "US"]:
        return "3943737998", "92EB4C721DB698B17C1BF61F8F7ECDEC55D814FB35ADA778FA5EE1DC0AEAEDFF"
    else:
        return "3943739516", "BFA0A0D9DF6D4EE1AA92354746475A429D775BCA4D8DD822ECBC6D0BF7B51886"

def get_jwt_token(region):
    uid, password = get_credentials(region)
    jwt_url = f"https://garenafreefirejwttokengeneratorclie.vercel.app/token?uid={uid}&password={password}"
    try:
        response = requests.get(jwt_url, timeout=10)
        if response.status_code != 200:
            print(f"JWT API returned status: {response.status_code}")
            return None
        data = response.json()
        print(f"JWT Response: {data}")
        return data
    except Exception as e:
        print(f"JWT Token Error: {str(e)}")
        return None

@app.route('/info', methods=['GET'])
def main():
    uid = request.args.get('uid')
    region = request.args.get('region')

    if not uid or not region:
        return jsonify({"error": "Missing 'uid' or 'region' query parameter"}), 400

    try:
        ujjaiwal_ = int(uid)
    except ValueError:
        return jsonify({"error": "Invalid UID"}), 400

    jwt_info = get_jwt_token(region)
    if not jwt_info or 'token' not in jwt_info:
        return jsonify({"error": "Failed to fetch valid JWT token"}), 500

    api = jwt_info.get('serverUrl', '')
    token = jwt_info.get('token', '')
    
    # Check if token already contains "Bearer " and remove our prefix if it does
    if token.startswith('Bearer '):
        auth_header = token  # Use as-is
    else:
        auth_header = f'Bearer {token}'  # Add prefix if missing
    
    if not api or not token:
        return jsonify({"error": "Invalid JWT response - missing serverUrl or token"}), 500

    # Create protobuf and encrypt
    protobuf_data = create_protobuf(ujjaiwal_, 1)
    hex_data = protobuf_to_hex(protobuf_data)
    encrypted_hex = encrypt_aes(hex_data, key, iv)

    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Authorization': auth_header,  # Use the corrected auth header
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB50',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip',
    }

    try:
        print(f"API Endpoint: {api}/GetPlayerPersonalShow")
        print(f"Auth Header: {auth_header[:50]}...")
        print(f"Encrypted data length: {len(encrypted_hex)}")
        
        # Convert hex to bytes for the request body
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        
        response = requests.post(
            f"{api}/GetPlayerPersonalShow", 
            headers=headers, 
            data=encrypted_bytes,
            timeout=15
        )
        
        print(f"Response Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        
        if response.status_code == 401:
            # Try alternative server if available
            if "ind.freefiremobile.com" in api:
                alt_api = api.replace("ind.freefiremobile.com", "clientbp.ggblueshark.com")
                print(f"Trying alternative server: {alt_api}")
                try:
                    response = requests.post(
                        f"{alt_api}/GetPlayerPersonalShow", 
                        headers=headers, 
                        data=encrypted_bytes,
                        timeout=15
                    )
                    response.raise_for_status()
                except:
                    return jsonify({
                        "error": "Authentication failed (401 Unauthorized) on both servers",
                        "details": "Server rejected the JWT token",
                        "servers_tried": [api, alt_api]
                    }), 401
            else:
                return jsonify({
                    "error": "Authentication failed (401 Unauthorized)",
                    "details": "Server rejected the JWT token",
                    "server": api
                }), 401
            
        response.raise_for_status()
        
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timeout to game server"}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Connection error to game server"}), 502
    except requests.exceptions.HTTPError as e:
        return jsonify({
            "error": f"HTTP error from game server: {str(e)}",
            "server": api,
            "status_code": response.status_code if 'response' in locals() else 'unknown'
        }), 502
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

    hex_response = response.content.hex()

    try:
        users = decode_hex(hex_response)
    except Exception as e:
        return jsonify({"error": f"Failed to parse Protobuf response: {str(e)}"}), 500

    result = {}

    if users.basicinfo:
        result['basicinfo'] = []
        for user_info in users.basicinfo:
            result['basicinfo'].append({
                'username': user_info.username,
                'region': user_info.region,
                'level': user_info.level,
                'Exp': user_info.Exp,
                'bio': users.bioinfo[0].bio if users.bioinfo and len(users.bioinfo) > 0 else None,
                'banner': user_info.banner,
                'avatar': user_info.avatar,
                'brrankscore': user_info.brrankscore,
                'BadgeCount': user_info.BadgeCount,
                'likes': user_info.likes,
                'lastlogin': user_info.lastlogin,
                'csrankpoint': user_info.csrankpoint,
                'csrankscore': user_info.csrankscore,
                'brrankpoint': user_info.brrankpoint,
                'createat': user_info.createat,
                'OB': user_info.OB,
                'primelevel': user_info.primelevel
            })

    if users.claninfo:
        result['claninfo'] = []
        for clan in users.claninfo:
            result['claninfo'].append({
                'clanid': clan.clanid,
                'clanname': clan.clanname,
                'guildlevel': clan.guildlevel,
                'livemember': clan.livemember
            })

    if users.clanadmin:
        result['clanadmin'] = []
        for admin in users.clanadmin:
            result['clanadmin'].append({
                'idadmin': admin.idadmin,
                'adminname': admin.adminname,
                'level': admin.level,
                'exp': admin.exp,
                'brpoint': admin.brpoint,
                'lastlogin': admin.lastlogin,
                'cspoint': admin.cspoint
            })

    result['primelevel'] = users.primelevel
    result['credit'] = '@Ujjaiwal'
    
    return jsonify(result)

@app.route('/jwt', methods=['GET'])
def test_jwt():
    region = request.args.get('region', 'IND')
    jwt_info = get_jwt_token(region)
    return jsonify(jwt_info if jwt_info else {"error": "Failed to get JWT"})

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "message": "Server is running"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)