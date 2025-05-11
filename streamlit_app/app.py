# app.py (主要なデバッグ箇所)
import streamlit as st
import jwt
from datetime import datetime, timezone
import os

print("--- app.py 読み込み開始 ---")

# --- 定数と設定 ---
AUTH_SERVER_LOGIN_URL_FROM_SECRETS = None
JWT_VERIFY_KEY_FROM_SECRETS = None
EXPECTED_STREAMLIT_AUDIENCE_FROM_SECRETS = None

try:
    AUTH_SERVER_LOGIN_URL_FROM_SECRETS = st.secrets.get("AUTH_SERVER_LOGIN_URL")
    JWT_VERIFY_KEY_FROM_SECRETS = st.secrets.get("JWT_VERIFY_KEY")
    EXPECTED_STREAMLIT_AUDIENCE_FROM_SECRETS = st.secrets.get("STREAMLIT_APP_URL")
    print("secrets.tomlから設定値を読み込みました (または試みました)。")
except (KeyError, FileNotFoundError, AttributeError): # AttributeError は st.secrets がない場合 (テストなど)
    print("secrets.tomlの読み込みに失敗したか、ファイルが存在しません。環境変数フォールバックを使用します。")

AUTH_SERVER_LOGIN_URL = AUTH_SERVER_LOGIN_URL_FROM_SECRETS or os.environ.get("AUTH_SERVER_LOGIN_URL", "http://localhost:8080/auth_login")
JWT_VERIFY_KEY = JWT_VERIFY_KEY_FROM_SECRETS or os.environ.get("JWT_VERIFY_KEY", "e1c5ef28797cba9a3d55ecd943520237fe4c8f68dbdf3b5a4b385167f04681bd")
EXPECTED_STREAMLIT_AUDIENCE = EXPECTED_STREAMLIT_AUDIENCE_FROM_SECRETS or os.environ.get("STREAMLIT_APP_URL", "http://localhost:8501")
JWT_ALGORITHM = "HS256"

print(f"Streamlit App: AUTH_SERVER_LOGIN_URL = {AUTH_SERVER_LOGIN_URL}")
print(f"Streamlit App: JWT_VERIFY_KEY = {JWT_VERIFY_KEY if JWT_VERIFY_KEY else None}...")
print(f"Streamlit App: EXPECTED_STREAMLIT_AUDIENCE = {EXPECTED_STREAMLIT_AUDIENCE}")
print("--- 設定値読み込み完了 ---")


# ... (セッションステート初期化、verify_auth_token関数は変更なし) ...
# (verify_auth_token内のエラーメッセージは既に詳細なので、ここでは大きな変更は不要)
if 'user_info' not in st.session_state:
    st.session_state['user_info'] = None
if 'auth_token_processed' not in st.session_state:
    st.session_state['auth_token_processed'] = False
if 'auth_error_processed' not in st.session_state:
    st.session_state['auth_error_processed'] = False

def verify_auth_token(token_string):
    if not token_string:
        st.error("検証する認証トークンがありません。")
        return None
    print(f"verify_auth_token: 検証対象トークン (先頭20文字): '{token_string[:20]}...'")
    print(f"verify_auth_token: 使用する検証キー (先頭5文字): '{JWT_VERIFY_KEY if JWT_VERIFY_KEY else None}...'")
    print(f"verify_auth_token: 期待するオーディエンス: '{EXPECTED_STREAMLIT_AUDIENCE}'")
    try:
        payload = jwt.decode(
            token_string,
            JWT_VERIFY_KEY,
            algorithms=[JWT_ALGORITHM],
            leeway=10,
            audience=EXPECTED_STREAMLIT_AUDIENCE
        )
        if 'exp' in payload:
            if datetime.utcfromtimestamp(payload['exp']) < datetime.utcnow():
                st.error("認証トークンの有効期限が切れています (verify_auth_token内)。")
                return None
        print("verify_auth_token: トークン検証成功。")
        return payload
    except jwt.ExpiredSignatureError:
        st.error("認証トークンの有効期限が切れています（ExpiredSignatureError）。")
        return None
    except jwt.InvalidAudienceError:
        # トークン内のaudクレームも表示してみる
        try:
            unverified_payload = jwt.decode(token_string, JWT_VERIFY_KEY, algorithms=[JWT_ALGORITHM], options={"verify_signature": False, "verify_exp": False, "verify_aud": False})
            token_aud = unverified_payload.get('aud')
        except Exception:
            token_aud = "取得失敗"
        st.error(f"無効なオーディエンスです。トークン内のaud: '{token_aud}', 期待値: '{EXPECTED_STREAMLIT_AUDIENCE}'")
        return None
    except jwt.InvalidTokenError as e:
        st.error(f"無効な認証トークンです (verify_auth_token内): {e}")
        return None
    except Exception as e:
        st.error(f"トークン検証中に予期せぬエラーが発生しました (verify_auth_token内): {e}")
        return None

# ... (メイン処理、UI表示部分は変更なし、ただしデバッグログが追加されている) ...
# (前回の app.py のメイン処理とUI表示部分をここに続ける)
st.set_page_config(page_title="Streamlit 外部認証テスト", layout="centered")
st.title("Streamlit 外部認証テスト (アクセス制御版)")

auth_error_val = None
if not st.session_state.get('auth_error_processed'):
    query_params_on_load = st.query_params
    auth_error_val = query_params_on_load.get("auth_error")
    if auth_error_val:
        error_message_key = auth_error_val[0] if isinstance(auth_error_val, list) else auth_error_val
        print(f"Streamlit App: auth_error_val = {error_message_key}") # エラー内容をログに
        if error_message_key == "unauthorized_user":
            st.error("アクセスが許可されていません。このアプリケーションを使用する権限がありません。")
        else:
            st.error(f"認証中にエラーが発生しました: {error_message_key}")
        st.query_params.clear()
        st.session_state['auth_error_processed'] = True
    else:
        st.session_state['auth_error_processed'] = True

if not st.session_state.get('user_info') and not st.session_state.get('auth_token_processed') and not auth_error_val:
    query_params_token = st.query_params
    token_str_from_url = query_params_token.get("auth_token")
    if token_str_from_url:
        token_to_verify = token_str_from_url[0] if isinstance(token_str_from_url, list) else token_str_from_url
        print(f"Streamlit App: URLから取得したトークン (先頭20文字): '{token_to_verify[:20]}...'")

        user_data_from_token = verify_auth_token(token_to_verify)
        if user_data_from_token:
            st.session_state['user_info'] = {
                "email": user_data_from_token.get("sub"),
                "name": user_data_from_token.get("name"),
            }
            st.success("ようこそ！認証に成功しました。")
            st.query_params.clear()
            st.session_state['auth_token_processed'] = True
            st.rerun()
        else:
            st.warning("認証トークンの検証に失敗しました。再度ログインをお試しください。 (メイン処理部)")
            st.session_state['auth_token_processed'] = True
            st.query_params.clear()
    else:
        st.session_state['auth_token_processed'] = True

if st.session_state.get('user_info'):
    st.header(f"ようこそ、{st.session_state['user_info'].get('name', 'ユーザー')}さん！")
    st.write("メールアドレス:", st.session_state['user_info'].get('email'))
    if st.button("ログアウト"):
        st.session_state['user_info'] = None
        st.session_state['auth_token_processed'] = False
        st.session_state['auth_error_processed'] = False
        st.success("ログアウトしました。")
        st.rerun()
elif not auth_error_val:
    st.header("ログインしてください")
    st.markdown(f"""
        <a href="{AUTH_SERVER_LOGIN_URL}" target="_self" style="
            display: inline-block; padding: 0.75em 1.5em; color: white;
            background-color: #4285F4; border: none; border-radius: 5px;
            text-align: center; text-decoration: none; font-size: 18px;
            font-weight: bold; cursor: pointer; box-shadow: 0 2px 4px 0 rgba(0,0,0,0.25);">
            Googleアカウントでログイン
        </a>
    """, unsafe_allow_html=True)
    st.caption("上記ボタンをクリックすると、Google認証ページへ遷移します。")

st.markdown("---")
with st.expander("デバッグ用セッション情報", expanded=False):
    st.write(st.session_state)

print("--- app.py 処理終了 ---")