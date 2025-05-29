from flask import Flask, request, jsonify
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor_pool, descriptor_pb2, message_factory

app = Flask(__name__)

# ---- secret.py contents ----
key = "Yg&tc%DEuh6%Zc^8"
iv = "6oyZDr22E3ychjM%"

# ---- Protobuf dynamic message definitions ----

pool = descriptor_pool.Default()

# Define uid_generator message descriptor
UID_GENERATOR_DESCRIPTOR = descriptor_pb2.FileDescriptorProto()
UID_GENERATOR_DESCRIPTOR.name = 'uid_generator.proto'
UID_GENERATOR_DESCRIPTOR.package = ''

msg_type = UID_GENERATOR_DESCRIPTOR.message_type.add()
msg_type.name = 'uid_generator'

field_akiru = msg_type.field.add()
field_akiru.name = 'akiru_'
field_akiru.number = 1
field_akiru.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
field_akiru.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT64

field_aditya = msg_type.field.add()
field_aditya.name = 'aditya'
field_aditya.number = 2
field_aditya.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
field_aditya.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT64

pool.Add(UID_GENERATOR_DESCRIPTOR)

factory = message_factory.MessageFactory(pool)

uid_generator_descriptor = pool.FindMessageTypeByName('uid_generator')
uid_generator = factory.GetPrototype(uid_generator_descriptor)


# Define zitado.proto messages

ZITADO_DESCRIPTOR = descriptor_pb2.FileDescriptorProto()
ZITADO_DESCRIPTOR.name = 'zitado.proto'
ZITADO_DESCRIPTOR.package = ''

# clan message
clan_msg = ZITADO_DESCRIPTOR.message_type.add()
clan_msg.name = 'clan'
clan_msg.field.add(name='clanid', number=1, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
clan_msg.field.add(name='clanname', number=2, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
clan_msg.field.add(name='guildlevel', number=4, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
clan_msg.field.add(name='livemember', number=5, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)

# adminclan message
adminclan_msg = ZITADO_DESCRIPTOR.message_type.add()
adminclan_msg.name = 'adminclan'
adminclan_msg.field.add(name='idadmin', number=1, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
adminclan_msg.field.add(name='adminname', number=3, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
adminclan_msg.field.add(name='level', number=6, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
adminclan_msg.field.add(name='exp', number=7, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
adminclan_msg.field.add(name='brpoint', number=15, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
adminclan_msg.field.add(name='cspoint', number=31, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
adminclan_msg.field.add(name='lastlogin', number=24, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)

# info message
info_msg = ZITADO_DESCRIPTOR.message_type.add()
info_msg.name = 'info'
info_msg.field.add(name='username', number=3, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
info_msg.field.add(name='region', number=5, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
info_msg.field.add(name='level', number=6, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='Exp', number=7, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='banner', number=11, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='avatar', number=12, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='likes', number=21, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='BadgeCount', number=18, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='lastlogin', number=24, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='createat', number=44, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='brrankpoint', number=35, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='brrankscore', number=15, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='csrankpoint', number=30, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='csrankscore', number=31, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)
info_msg.field.add(name='OB', number=50, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

# bio message
bio_msg = ZITADO_DESCRIPTOR.message_type.add()
bio_msg.name = 'bio'
bio_msg.field.add(name='bio', number=9, label=descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL, type=descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

# users message
users_msg = ZITADO_DESCRIPTOR.message_type.add()
users_msg.name = 'Users'
users_msg.field.add(name='claninfo', number=6, label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED, type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, type_name='clan')
users_msg.field.add(name='basicinfo', number=1, label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED, type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, type_name='info')
users_msg.field.add(name='clanadmin', number=7, label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED, type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, type_name='adminclan')
users_msg.field.add(name='bioinfo', number=9, label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED, type=descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, type_name='bio')

pool.Add(ZITADO_DESCRIPTOR)

users_descriptor = pool.FindMessageTypeByName('Users')
users_class = factory.GetPrototype(users_descriptor)


# ---- Helper functions ----

def create_protobuf(akiru_, aditya):
    msg = uid_generator()
    msg.akiru_ = akiru_
    msg.aditya = aditya
    return msg.SerializeToString()

def encrypt_aes(hex_data, key, iv):
    key_bytes = key.encode()[:16]
    iv_bytes = iv.encode()[:16]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string)
    users = users_class()
    users.ParseFromString(byte_data)
    return users

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


@app.route('/player-info', methods=['GET'])
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