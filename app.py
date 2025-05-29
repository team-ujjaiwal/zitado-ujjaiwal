from flask import Flask, request, jsonify
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import message
from google.protobuf import descriptor_pool, descriptor_pb2, symbol_database

app = Flask(__name__)

# ---- secret.py contents ----
key = "Yg&tc%DEuh6%Zc^8"
iv = "6oyZDr22E3ychjM%"

# ---- Minimal protobuf emulation for uid_generator_pb2 ----
# Normally, you import uid_generator_pb2 compiled from .proto.
# Here we define a minimal protobuf message class for uid_generator.

from google.protobuf import descriptor as _descriptor
from google.protobuf import message_factory as _message_factory
from google.protobuf import descriptor_pool as _descriptor_pool

pool = _descriptor_pool.Default()

UID_GENERATOR_DESCRIPTOR = descriptor_pb2.FileDescriptorProto()
UID_GENERATOR_DESCRIPTOR.name = 'uid_generator.proto'
UID_GENERATOR_DESCRIPTOR.package = ''
UID_GENERATOR_DESCRIPTOR.message_type.add().name = 'uid_generator'
UID_GENERATOR_DESCRIPTOR.message_type[0].field.add(
    name='akiru_', number=1, type=3, label=1)  # int64, optional
UID_GENERATOR_DESCRIPTOR.message_type[0].field.add(
    name='aditya', number=2, type=3, label=1)  # int64, optional

pool.Add(UID_GENERATOR_DESCRIPTOR)

factory = _message_factory.MessageFactory(pool)
uid_generator = factory.GetPrototype(pool.FindMessageTypeByName('uid_generator'))

# ---- Minimal protobuf emulation for zitado_pb2 ----

ZITADO_DESCRIPTOR = descriptor_pb2.FileDescriptorProto()
ZITADO_DESCRIPTOR.name = 'zitado.proto'
ZITADO_DESCRIPTOR.package = ''

# clan message
clan_msg = ZITADO_DESCRIPTOR.message_type.add()
clan_msg.name = 'clan'
clan_msg.field.add(name='clanid', number=1, type=13, label=1)       # uint32
clan_msg.field.add(name='clanname', number=2, type=9, label=1)      # string
clan_msg.field.add(name='guildlevel', number=4, type=13, label=1)   # uint32
clan_msg.field.add(name='livemember', number=5, type=13, label=1)   # uint32

# adminclan message
adminclan_msg = ZITADO_DESCRIPTOR.message_type.add()
adminclan_msg.name = 'adminclan'
adminclan_msg.field.add(name='idadmin', number=1, type=13, label=1)      # uint32
adminclan_msg.field.add(name='adminname', number=3, type=9, label=1)     # string
adminclan_msg.field.add(name='level', number=6, type=13, label=1)         # uint32
adminclan_msg.field.add(name='exp', number=7, type=13, label=1)           # uint32
adminclan_msg.field.add(name='brpoint', number=15, type=13, label=1)      # uint32
adminclan_msg.field.add(name='cspoint', number=31, type=13, label=1)      # uint32
adminclan_msg.field.add(name='lastlogin', number=24, type=13, label=1)    # uint32

# info message
info_msg = ZITADO_DESCRIPTOR.message_type.add()
info_msg.name = 'info'
info_msg.field.add(name='username', number=3, type=9, label=1)       # string
info_msg.field.add(name='region', number=5, type=9, label=1)         # string
info_msg.field.add(name='level', number=6, type=13, label=1)         # uint32
info_msg.field.add(name='Exp', number=7, type=13, label=1)            # uint32
info_msg.field.add(name='banner', number=11, type=13, label=1)       # uint32
info_msg.field.add(name='avatar', number=12, type=13, label=1)       # uint32
info_msg.field.add(name='likes', number=21, type=13, label=1)        # uint32
info_msg.field.add(name='BadgeCount', number=18, type=13, label=1)   # uint32
info_msg.field.add(name='lastlogin', number=24, type=13, label=1)    # uint32
info_msg.field.add(name='createat', number=44, type=13, label=1)     # uint32
info_msg.field.add(name='brrankpoint', number=35, type=13, label=1)  # uint32
info_msg.field.add(name='brrankscore', number=15, type=13, label=1)  # uint32
info_msg.field.add(name='csrankpoint', number=30, type=13, label=1)  # uint32
info_msg.field.add(name='csrankscore', number=31, type=13, label=1)  # uint32
info_msg.field.add(name='OB', number=50, type=9, label=1)             # string

# bio message (for bio info)
bio_msg = ZITADO_DESCRIPTOR.message_type.add()
bio_msg.name = 'bio'
bio_msg.field.add(name='bio', number=9, type=9, label=1)  # string

# users message
users_msg = ZITADO_DESCRIPTOR.message_type.add()
users_msg.name = 'Users'
users_msg.field.add(name='claninfo', number=6, type=11, label=3, type_name='clan')
users_msg.field.add(name='basicinfo', number=1, type=11, label=3, type_name='info')
users_msg.field.add(name='clanadmin', number=7, type=11, label=3, type_name='adminclan')
users_msg.field.add(name='bioinfo', number=9, type=11, label=3, type_name='bio')

pool.Add(ZITADO_DESCRIPTOR)
users_class = factory.GetPrototype(pool.FindMessageTypeByName('Users'))

# ---- Helper functions ----

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def create_protobuf(akiru_, aditya):
    message = uid_generator()
    message.akiru_ = akiru_
    message.aditya = aditya
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = users_class()
    users.ParseFromString(byte_data)
    return users

def encrypt_aes(hex_data, key, iv):
    key_bytes = key.encode()[:16]
    iv_bytes = iv.encode()[:16]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
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
    jwt_url = f"https://jwt-aditya.vercel.app/token?uid={uid}&password={password}"
    response = requests.get(jwt_url)
    if response.status_code != 200:
        return None
    return response.json()

@app.route('/player', methods=['GET'])
def main():
    uid = request.args.get('uid')
    region = request.args.get('region')

    if not uid or not region:
        return jsonify({"error": "Missing 'uid' or 'region' query parameter"}), 400

    try:
        saturn_ = int(uid)
    except ValueError:
        return jsonify({"error": "Invalid UID"}), 400

    jwt_info = get_jwt_token(region)
    if not jwt_info or 'token' not in jwt_info:
        return jsonify({"error": "Failed to fetch JWT token"}), 500

    api = jwt_info['api']
    token = jwt_info['token']

    protobuf_data = create_protobuf(saturn_, 1)
    hex_data = protobuf_to_hex(protobuf_data)
    encrypted_hex = encrypt_aes(hex_data, key, iv)

    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 13; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB49',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    try:
        response = requests.post(f"{api}/GetPlayerPersonalShow", headers=headers, data=bytes.fromhex(encrypted_hex))
        response.raise_for_status()
    except requests.RequestException:
        return jsonify({"error": "Failed to contact game server"}), 502

    hex_response = response.content.hex()

    try:
        users = decode_hex(hex_response)
    except Exception as e:
        return jsonify({"error": f"Failed to parse Protobuf: {str(e)}"}), 500

    result = {}

    if users.basicinfo:
        result['basicinfo'] = []
        for user_info in users.basicinfo:
            result['basicinfo'].append({
                'username': user_info.username,
                'region': user_info.region,
                'level': user_info.level,
                'Exp': user_info.Exp,
                'bio': users.bioinfo[0].bio if users.bioinfo else None,
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
                'OB': user_info.OB
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

    result['credit'] = '@Ujjaiwal'
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)