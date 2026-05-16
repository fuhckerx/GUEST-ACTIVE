# login_api.py
import asyncio
from flask import Flask, request, jsonify
from JwtGen import (
    GeNeRaTeAccEss, EncRypTMajoRLoGin, MajorLogin,
    DecRypTMajoRLoGin, GetLoginData, DecRypTLoGinDaTa, xAuThSTarTuP
)

app = Flask(__name__)

async def login_account(uid: str, password: str):
    """
    Perform full Free Fire login and return connection data.
    """
    try:
        open_id, access_token = await GeNeRaTeAccEss(uid, password)
        if not open_id or not access_token:
            return {"success": False, "error": "Invalid credentials or network issue"}

        payload = await EncRypTMajoRLoGin(open_id, access_token)
        login_res = await MajorLogin(payload)
        if not login_res:
            return {"success": False, "error": "MajorLogin failed (account banned or server error)"}

        dec = await DecRypTMajoRLoGin(login_res)
        key = dec.key.hex() if isinstance(dec.key, bytes) else dec.key
        iv = dec.iv.hex() if isinstance(dec.iv, bytes) else dec.iv
        token = dec.token
        timestamp = dec.timestamp
        account_uid = dec.account_uid

        login_data = await GetLoginData(dec.url, payload, token)
        if not login_data:
            return {"success": False, "error": "Failed to get login data (ports)"}

        ports = await DecRypTLoGinDaTa(login_data)
        online_ip, online_port = ports.Online_IP_Port.split(":")
        chat_ip, chat_port = ports.AccountIP_Port.split(":")

        auth_token = await xAuThSTarTuP(
            int(account_uid), token, int(timestamp),
            bytes.fromhex(key), bytes.fromhex(iv)
        )

        return {
            "success": True,
            "uid": account_uid,
            "key": key,
            "iv": iv,
            "token": token,
            "online_ip": online_ip,
            "online_port": int(online_port),
            "chat_ip": chat_ip,
            "chat_port": int(chat_port),
            "auth_token": auth_token,
            "region": getattr(ports, "Region", None),
            "account_name": getattr(ports, "AccountName", None)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.route('/login', methods=['GET'])
def login_endpoint():
    uid = request.args.get('uid')
    password = request.args.get('pass')
    if not uid or not password:
        return jsonify({
            "credit": "CREATE BY FX FuhX",
            "error": "uid and pass parameters are required"
        }), 400

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(login_account(uid, password))
    loop.close()

    # Add credit to response
    result["credit"] = "CREATE BY FX FuhX"
    
    if result.get("success"):
        return jsonify(result), 200
    else:
        return jsonify(result), 401

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "credit": "CREATE BY FX FuhX",
        "message": "Free Fire Login API",
        "endpoints": {
            "/login?uid=YOUR_UID&pass=YOUR_PASSWORD": "POST or GET request to login"
        }
    })

if __name__ == '__main__':
    print("\n========================================")
    print("   🔥 Free Fire Login API by FX FuhX 🔥")
    print("========================================")
    print(f"📍 Server running at: http://localhost:5000")
    print(f"📌 Use: http://localhost:5000/login?uid=123456&pass=yourpass")
    print("========================================\n")
    app.run(host='0.0.0.0', port=5000, debug=False)