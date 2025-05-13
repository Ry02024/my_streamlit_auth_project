# main.py
import os
import uuid
from datetime import datetime, timedelta, timezone

import firebase_admin
from firebase_admin import credentials, firestore
from flask import Flask, redirect, request, make_response # Flaskは後で初期化
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleAuthRequest
import jwt
from dotenv import load_dotenv

print("--- main.py 読み込み開始 ---")

# --- グローバル変数のプレースホルダー ---
GCP_PROJECT_ID = None
GOOGLE_CLIENT_ID = None
GOOGLE_CLIENT_SECRET = None
JWT_SECRET_KEY = None
STREAMLIT_APP_URL = None
db = None
FUNCTION_BASE_URL = None
REDIRECT_URI = None
ALLOWED_USERS_LIST = [] # 初期化

# --- 設定読み込みと初期化を行う関数 ---
def initialize_app_configs():
    global GCP_PROJECT_ID, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET_KEY, STREAMLIT_APP_URL
    global db, FUNCTION_BASE_URL, REDIRECT_URI, ALLOWED_USERS_LIST, secret_manager_client, CAN_USE_SECRET_MANAGER

    dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(dotenv_path):
        print(f"ローカルテスト用に '{dotenv_path}' から環境変数を読み込みます。")
        load_dotenv(dotenv_path)
    else:
        print(f"警告: '.env' ファイルが見つかりません。")

    # GCPプロジェクトIDの設定
    gcp_project_env = os.environ.get('GCP_PROJECT')
    gcp_project_gcloud = None
    try:
        import subprocess
        gcp_project_gcloud = subprocess.check_output(['gcloud', 'config', 'get-value', 'project'], text=True).strip()
    except Exception: pass
    if gcp_project_env: GCP_PROJECT_ID = gcp_project_env
    elif gcp_project_gcloud: GCP_PROJECT_ID = gcp_project_gcloud
    else: GCP_PROJECT_ID = "★ YOUR_GCP_PROJECT_ID_FALLBACK ★"
    if GCP_PROJECT_ID == "★ YOUR_GCP_PROJECT_ID_FALLBACK ★":
        print(f"警告: プロジェクトIDが特定できませんでした。フォールバック値 '{GCP_PROJECT_ID}' を使用します。")
    else:
        print(f"GCPプロジェクトIDを設定: {GCP_PROJECT_ID}")


    # Secret Managerクライアントの初期化
    secret_manager_client = None
    CAN_USE_SECRET_MANAGER = False
    try:
        from google.cloud import secretmanager
        secret_manager_client = secretmanager.SecretManagerServiceClient()
        CAN_USE_SECRET_MANAGER = True
        print("Secret Managerクライアントを初期化しました。")
    except ImportError: print("警告: google-cloud-secret-manager がインポートできませんでした。")
    except Exception as e: print(f"警告: Secret Managerクライアントの初期化に失敗: {e}")

    # get_secret 関数の定義 (initialize_app_configs 内に移動しても良いが、グローバルでも可)
    # この関数は CAN_USE_SECRET_MANAGER, GCP_PROJECT_ID, secret_manager_client を参照する
    # (get_secret 関数の定義は変更なし - 前回のものをここに配置)
    def get_secret_local(secret_id, version_id="latest"): # ローカルスコープなので名前変更
        env_val = os.environ.get(secret_id)
        if env_val: return env_val.strip()
        if not CAN_USE_SECRET_MANAGER or not GCP_PROJECT_ID or GCP_PROJECT_ID == "★ YOUR_GCP_PROJECT_ID_FALLBACK ★": return None
        name = f"projects/{GCP_PROJECT_ID}/secrets/{secret_id}/versions/{version_id}"
        try:
            response = secret_manager_client.access_secret_version(request={"name": name})
            value_from_sm = response.payload.data.decode("UTF-8")
            return value_from_sm.strip()
        except Exception as e: print(f"SMからの取得失敗 ({secret_id}): {e}"); return None

    print("--- シークレット読み込み開始 ---")
    GOOGLE_CLIENT_ID = get_secret_local("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = get_secret_local("GOOGLE_CLIENT_SECRET")
    JWT_SECRET_KEY = get_secret_local("JWT_SECRET_KEY")
    STREAMLIT_APP_URL = get_secret_local("STREAMLIT_APP_URL")
    print(f"読み込み後の GOOGLE_CLIENT_ID: '{GOOGLE_CLIENT_ID}'")
    print(f"読み込み後の GOOGLE_CLIENT_SECRET: '{GOOGLE_CLIENT_SECRET[:5] if GOOGLE_CLIENT_SECRET else None}...'")
    # ... 他のシークレットのprint文 ...
    print("--- シークレット読み込み完了 ---")

    if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SECRET_KEY, STREAMLIT_APP_URL]):
        missing = [name for name, var in [...] if not var] # 前回同様
        raise ValueError(f"起動に必要なシークレットが設定されていません: {', '.join(missing)}.")

    # Firestoreクライアントの初期化
    try:
        if not firebase_admin._apps:
            print(f"Firebase Admin SDKを初期化 (プロジェクトID: {GCP_PROJECT_ID})")
            cred = credentials.ApplicationDefault()
            firebase_admin.initialize_app(cred, {'projectId': GCP_PROJECT_ID})
        db = firestore.client()
        print("Firestoreクライアント初期化成功")
    except Exception as e: raise RuntimeError(f"Firestore初期化失敗: {e}")

    # OAuth設定
    CALLBACK_FUNCTION_NAME = "auth_callback"
    CF_REGION = os.environ.get('FUNCTION_REGION', 'asia-northeast1')
    # FUNCTION_BASE_URL の決定 (ENV変数を考慮)
    if os.environ.get('ENV') == 'local':
        FUNCTION_BASE_URL = os.environ.get("FUNCTION_BASE_URL", "http://localhost:8080")
    else: # デプロイ時
        FUNCTION_BASE_URL = f"https://{CF_REGION}-{GCP_PROJECT_ID}.cloudfunctions.net"
    print(f"FUNCTION_BASE_URL を '{FUNCTION_BASE_URL}' に設定しました。")

    REDIRECT_URI = f"{FUNCTION_BASE_URL}/{CALLBACK_FUNCTION_NAME}"
    print(f"REDIRECT_URI を '{REDIRECT_URI}' に設定しました。")

    # ALLOWED_USERS_LIST (変更なし)
    ALLOWED_USERS_LIST = [
        "tan0ry02024@gmail.com",
        "tan0ry0@gmail.com"
    ]

# --- Flaskアプリのインスタンス化 (設定読み込み後) ---
initialize_app_configs() # ★★★ 設定と初期化を最初に実行 ★★★
app = Flask(__name__)    # ★★★ Flaskアプリのインスタンス化をここで行う ★★★

# --- 定数 (initialize_app_configsの後ならグローバル変数を参照可能) ---
SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
STATE_COLLECTION = "oauth_states"
NONCE_COOKIE_NAME = "oauth_nonce"


# --- /login エンドポイント ---
@app.route('/auth_login', methods=['GET'])
def auth_login_route():
    # この関数内では、GCP_PROJECT_ID, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI などは
    # initialize_app_configs() によってグローバルスコープに設定済みのはず
    print("\n--- /auth_login accessed ---")
    print(f"使用する GOOGLE_CLIENT_ID: {GOOGLE_CLIENT_ID}")
    print(f"使用する REDIRECT_URI (Flow初期化時): {REDIRECT_URI}")

    client_config_dict = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID, # .strip() は get_secret_local 内で行う
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "project_id": GCP_PROJECT_ID,
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "redirect_uris": [REDIRECT_URI],
        }
    }
    # ... (以降のauth_login_routeのロジックは前回と同様、ただし変数は加工済みのものを使う) ...
    # (Flowオブジェクトの初期化、Firestoreへの保存、authorization_url生成、リダイレクト処理)
    try:
        flow = Flow.from_client_config(
            client_config=client_config_dict,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
    except Exception as e:
        print(f"Flowオブジェクトの初期化に失敗: {e}")
        return f"OAuth設定エラー: {e}", 500

    print(f"Flowオブジェクトの redirect_uri: {flow.redirect_uri}")

    oauth_state_param = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    try:
        state_doc_ref = db.collection(STATE_COLLECTION).document(nonce)
        state_data = {"state": oauth_state_param, "created_at": firestore.SERVER_TIMESTAMP}
        state_doc_ref.set(state_data)
        print(f"Firestoreに Nonce '{nonce}' と State '{oauth_state_param}' を保存しました。")
    except Exception as e:
        print(f"FirestoreへのState保存に失敗: {e}")
        return f"内部エラー(State保存失敗): {e}", 500

    authorization_url, state_sent_to_google = flow.authorization_url(
        access_type='offline',
        state=oauth_state_param
    )
    print(f"生成されたGoogle認証URL (全体): {authorization_url}")

    response = make_response(redirect(authorization_url))
    secure_cookie = not (os.environ.get('ENV') == 'local')
    response.set_cookie(NONCE_COOKIE_NAME, nonce, max_age=600, httponly=True, secure=secure_cookie, samesite='Lax')
    print(f"Nonce Cookie '{NONCE_COOKIE_NAME}' をセットしました。Googleへリダイレクトします。")
    return response

# --- /callback エンドポイント ---
@app.route('/auth_callback', methods=['GET'])
def auth_callback_route():
    # この関数内でも、GCP_PROJECT_ID, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI,
    # STREAMLIT_APP_URL, JWT_SECRET_KEY, ALLOWED_USERS_LIST などはグローバルスコープから参照
    print("\n--- /auth_callback accessed ---")
    # ... (以降のauth_callback_routeのロジックは前回と同様) ...
    # (state検証, トークン取得, IDトークン検証, アクセス制御, JWT生成, リダイレクト)
    returned_state = request.args.get('state')
    code = request.args.get('code')
    print(f"Callback: returned_state='{returned_state}', code='{code[:10] if code else None}...'")

    error = request.args.get('error')
    if error: # (省略 - 前回同様)
        print(f"Callback Error from Google: {error}")
        return f"認証エラー (Googleより): {error}", 400
    if not code: # (省略 - 前回同様)
        print("Callback Error: No code from Google.")
        return "認証コードがGoogleから提供されませんでした。", 400

    nonce = request.cookies.get(NONCE_COOKIE_NAME)
    if not nonce: # (省略 - 前回同様)
        print("Callback Error: Nonce Cookie not found.")
        return "Nonce Cookieが見つかりません。セッションが無効か、Cookieがブロックされています。", 400
    print(f"Callback: Retrieved Nonce from cookie: '{nonce}'")

    try: # (省略 - 前回同様)
        state_doc_ref = db.collection(STATE_COLLECTION).document(nonce)
        state_doc = state_doc_ref.get()
    except Exception as e:
        print(f"Callback Error: Firestore access failed for nonce '{nonce}': {e}")
        return f"内部エラー(State取得失敗): {e}", 500

    if not state_doc.exists: # (省略 - 前回同様)
        print(f"Callback Error: State for nonce '{nonce}' not found in Firestore.")
        return "Firestoreに保存されたState情報が見つかりません。有効期限切れか不正なNonceです。", 400

    expected_state = state_doc.to_dict().get("state")
    print(f"Callback: Expected state from Firestore: '{expected_state}'")
    state_doc_ref.delete()
    if returned_state != expected_state: # (省略 - 前回同様)
        print(f"Callback Error: State mismatch. Expected: '{expected_state}', Returned: '{returned_state}'")
        return "Stateパラメータが一致しません。CSRF攻撃の可能性があります。", 400

    print("Callback: State validation successful. Fetching token from Google.")
    client_config_dict_callback = { # (省略 - 前回同様)
        "web": {
            "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "project_id": GCP_PROJECT_ID,
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "redirect_uris": [REDIRECT_URI],
        }
    }
    flow = Flow.from_client_config(client_config=client_config_dict_callback, scopes=SCOPES, state=expected_state)
    flow.redirect_uri = REDIRECT_URI

    try: # (省略 - 前回同様)
        flow.fetch_token(code=code)
        credentials = flow.credentials
        print(f"Callback: Successfully fetched token from Google. Access token (type): {type(credentials.token)}")
    except Exception as e:
        print(f"Callback Error: Failed to fetch token from Google: {e}")
        return f"Googleからのトークン取得に失敗しました: {e}", 500

    # --- ▼▼▼ ここからデバッグログとIDトークン検証 ▼▼▼ ---
    try:
        # --- デバッグ用: IDトークンの中身と時刻を事前に確認 ---
        if credentials.id_token:
            try:
                # PyJWTを使って署名検証なしでデコードし、時刻クレームを確認
                # これはあくまでデバッグ目的で、実際の検証は id_token.verify_oauth2_token で行う
                unverified_payload_for_debug = jwt.decode(
                    credentials.id_token,
                    options={"verify_signature": False, "verify_exp": False, "verify_iat": False, "verify_nbf": False, "verify_aud": False, "verify_iss": False}
                )
                iat_from_token = unverified_payload_for_debug.get('iat')
                nbf_from_token = unverified_payload_for_debug.get('nbf')
                exp_from_token = unverified_payload_for_debug.get('exp')
                current_utc_timestamp = int(datetime.now(timezone.utc).timestamp()) # 現在のUNIXタイムスタンプ(UTC)

                print(f"DEBUG Callback: Current Server UTC Timestamp = {current_utc_timestamp} ({datetime.fromtimestamp(current_utc_timestamp, timezone.utc).isoformat()})")
                if iat_from_token:
                    print(f"DEBUG Callback: ID Token 'iat' (Issued At) = {iat_from_token} ({datetime.fromtimestamp(iat_from_token, timezone.utc).isoformat()}) (Diff with current: {current_utc_timestamp - iat_from_token}s)")
                if nbf_from_token:
                    print(f"DEBUG Callback: ID Token 'nbf' (Not Before) = {nbf_from_token} ({datetime.fromtimestamp(nbf_from_token, timezone.utc).isoformat()}) (Diff with current: {current_utc_timestamp - nbf_from_token}s)")
                if exp_from_token:
                    print(f"DEBUG Callback: ID Token 'exp' (Expiration) = {exp_from_token} ({datetime.fromtimestamp(exp_from_token, timezone.utc).isoformat()}) (Remaining: {exp_from_token - current_utc_timestamp}s)")
            except Exception as debug_e:
                print(f"DEBUG Callback: IDトークンのデバッグ用デコード中にエラー: {debug_e}")
        # --- デバッグ用コード終了 ---

        # 実際のIDトークン検証
        print("DEBUG Callback: Calling id_token.verify_oauth2_token()...")
        id_info = id_token.verify_oauth2_token(credentials.id_token, GoogleAuthRequest(), GOOGLE_CLIENT_ID)
        user_email = id_info.get("email")
        user_name = id_info.get("name")
        print(f"Callback: ID token verified. Email: {user_email}, Name: {user_name}")

        # --- アクセス制御ロジック ---
        print(f"DEBUG Callback: ALLOWED_USERS_LIST = {ALLOWED_USERS_LIST}") # リストの内容をログに出力
        is_allowed = False
        if user_email: # user_emailがNoneでないことを確認
            normalized_user_email = user_email.lower().strip() # 小文字化と比較前後の空白除去
            for allowed_email in ALLOWED_USERS_LIST:
                normalized_allowed_email = allowed_email.lower().strip()
                print(f"DEBUG Callback: Comparing '{normalized_user_email}' with '{normalized_allowed_email}'") # 比較対象をログに
                if normalized_user_email == normalized_allowed_email:
                    is_allowed = True
                    break
        
        if not is_allowed:
            print(f"Callback Warning: User '{user_email}' (normalized: '{normalized_user_email if user_email else 'N/A'}') is not in ALLOWED_USERS_LIST. Access denied.")
            error_redirect_url = f"{STREAMLIT_APP_URL}?auth_error=unauthorized_user"
            # ... (エラーリダイレクト処理) ...
        else:
            print(f"Callback Info: User '{user_email}' (normalized: '{normalized_user_email}') is allowed. Generating JWT.")
        # --- アクセス制御ロジック終了 ---

    except Exception as e:
        print(f"Callback Error: Failed to verify ID token or during access control: {e}") # エラーメッセージに詳細が含まれるはず
        return f"ユーザー情報の検証またはアクセス制御に失敗しました: {e}", 500
    # --- ▲▲▲ ここまでデバッグログとIDトークン検証 ▲▲▲ ---

    try: # (省略 - 前回同様)
        id_info = id_token.verify_oauth2_token(credentials.id_token, GoogleAuthRequest(), GOOGLE_CLIENT_ID)
        user_email = id_info.get("email")
        user_name = id_info.get("name")
        print(f"Callback: ID token verified. Email: {user_email}, Name: {user_name}")

        if user_email not in ALLOWED_USERS_LIST: # (省略 - 前回同様)
            print(f"Callback Warning: User {user_email} is not in ALLOWED_USERS_LIST. Access denied.")
            error_redirect_url = f"{STREAMLIT_APP_URL}?auth_error=unauthorized_user"
            response = make_response(redirect(error_redirect_url))
            secure_cookie = not (os.environ.get('ENV') == 'local')
            response.delete_cookie(NONCE_COOKIE_NAME, path='/', secure=secure_cookie, httponly=True, samesite='Lax')
            return response
        else:
            print(f"Callback Info: User {user_email} is allowed. Generating JWT.")

    except Exception as e: # (省略 - 前回同様)
        print(f"Callback Error: Failed to verify ID token or during access control: {e}")
        return f"ユーザー情報の検証またはアクセス制御に失敗しました: {e}", 500

    jwt_payload = { # (省略 - 前回同様)
        "sub": user_email, "name": user_name, "email": user_email,
        "iss": FUNCTION_BASE_URL, "aud": STREAMLIT_APP_URL,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc)
    }
    try: # (省略 - 前回同様)
        jwt_token = jwt.encode(jwt_payload, JWT_SECRET_KEY, algorithm="HS256")
        print(f"Callback: JWT generated successfully. Token (first 20 chars): {jwt_token[:20]}...")
    except Exception as e:
        print(f"Callback Error: Failed to generate JWT: {e}")
        return f"認証トークン(JWT)の生成に失敗しました: {e}", 500

    target_url = f"{STREAMLIT_APP_URL}?auth_token={jwt_token}" # (省略 - 前回同様)
    response = make_response(redirect(target_url))
    secure_cookie = not (os.environ.get('ENV') == 'local')
    response.delete_cookie(NONCE_COOKIE_NAME, path='/', secure=secure_cookie, httponly=True, samesite='Lax')
    print(f"Callback: Redirecting to Streamlit app: {target_url[:len(STREAMLIT_APP_URL)+20]}...")
    return response


if __name__ == '__main__':
    os.environ['ENV'] = 'local' # ローカル実行フラグを先に設定
    initialize_app_configs()    # ★★★ mainブロックの最初に設定読み込みを実行 ★★★

    # 以下のprint文は initialize_app_configs() の後ならグローバル変数を参照できる
    print(f"\n--- ローカルサーバー起動準備完了 ---")
    print(f"使用するGCPプロジェクト: '{GCP_PROJECT_ID}'")
    print(f"OAuthクライアントID (main.py内): '{GOOGLE_CLIENT_ID}'")
    print(f"Streamlitリダイレクト先 (main.py内 JWT aud): '{STREAMLIT_APP_URL}'")
    print(f"ローカル認証サーバーベースURL (main.py内): '{FUNCTION_BASE_URL}'") # これはinitialize_app_configsで設定される
    print(f"ログインエンドポイント: {FUNCTION_BASE_URL}/auth_login")
    print(f"コールバックエンドポイント: {REDIRECT_URI} (これがGCPコンソールのリダイレクトURIと一致確認)") # REDIRECT_URIもinitialize_app_configsで設定
    print(f"---------------------------------")
    app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)
