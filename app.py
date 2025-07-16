import streamlit as st
import requests
from datetime import datetime

# Configurações de usuário permitido
USUARIO_PERMITIDO = "yasmin"
SENHA_PERMITIDA = "Senha123"  # Substitua pela sua senha segura

# Configurações da API
BASE_URL = "https://api.maas-moura.com"
EMAIL_API = "yasmin.mota@grupomoura.com"      # Seu login de API
SENHA_API = "Yasmim@2023"        # Sua senha de API

def obter_token():
    url = f"{BASE_URL}/auth/login"
    payload = {"email": EMAIL_API, "password": SENHA_API}
    r = requests.post(url, json=payload)
    if r.status_code == 200:
        return r.json().get("token")
    return None

def consultar_alarmes(site_id, token):
    url = f"{BASE_URL}/alarms/findOpenAlarmsById/{site_id}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return None
    try:
        data = r.json()
        if not data:
            return "vazio"
        elif isinstance(data, list) and "alertName" not in data[0]:
            return "invalido"
        else:
            return data
    except:
        return None

# Inicializa estado
if 'login_ok' not in st.session_state:
    st.session_state['login_ok'] = False
if 'page' not in st.session_state:
    st.session_state['page'] = 'login'
if 'site_id' not in st.session_state:
    st.session_state['site_id'] = ''
if 'login_error' not in st.session_state:
    st.session_state['login_error'] = False

def tentar_login(usuario, senha):
    if usuario == USUARIO_PERMITIDO and senha == SENHA_PERMITIDA:
        st.session_state['login_ok'] = True
        st.session_state['page'] = 'consulta'
        st.session_state['login_error'] = False
    else:
        st.session_state['login_error'] = True

def ir_para_resultados():
    if st.session_state['site_input'].strip() == "":
        st.warning("Por favor, digite o ID do site.")
    else:
        st.session_state['site_id'] = st.session_state['site_input'].strip().upper()
        st.session_state['page'] = 'resultados'

def voltar_para_consulta():
    st.session_state['page'] = 'consulta'

def voltar_para_login():
    st.session_state['page'] = 'login'
    st.session_state['login_ok'] = False
    st.session_state['login_error'] = False

# --- TELA LOGIN ---
if st.session_state['page'] == 'login':
    st.title("🔐 Login de acesso")
    usuario = st.text_input("Usuário", key="usuario")
    senha = st.text_input("Senha", type="password", key="senha")
    st.button("Entrar", on_click=tentar_login, args=(usuario, senha))
    if st.session_state['login_error']:
        st.error("Usuário ou senha incorretos")

# --- TELA CONSULTA ---
elif st.session_state['page'] == 'consulta':
    if not st.session_state['login_ok']:
        st.error("Você precisa estar logado.")
        st.button("Voltar ao login", on_click=voltar_para_login)
    else:
        st.title("🚨 Consulta de Alarmes - MOURA")
        st.text_input("🏷️ Digite o ID do site (ex: PEFCX)", key="site_input")
        st.button("Consultar", on_click=ir_para_resultados)

# --- TELA RESULTADOS ---
elif st.session_state['page'] == 'resultados':
    st.title(f"📋 Resultados para o site {st.session_state['site_id']}")
    token = obter_token()
    if not token:
        st.error("Erro ao obter token. Volte e tente novamente.")
        st.button("Voltar", on_click=voltar_para_consulta)
    else:
        resultado = consultar_alarmes(st.session_state['site_id'], token)
        if resultado == "vazio":
            st.success("✅ Site sem alarmes ativos ou inexistente.")
        elif resultado == "invalido":
            st.error("❌ Site inválido ou resposta inesperada da API.")
        elif isinstance(resultado, list):
            st.info(f"🔎 {len(resultado)} alarme(s) encontrado(s):")
            for alarme in resultado:
                data_formatada = datetime.fromisoformat(
                    alarme["startDate"].replace("Z", "+00:00")
                ).strftime("%d/%m/%Y %H:%M:%S")
                st.warning(
                    f"[{alarme['alertLevel'].upper()}] {alarme['alertName']} - desde {data_formatada} (Cód. {alarme['alertCode']})"
                )
        else:
            st.error("❌ Erro ao processar resposta da API.")

        st.button("Nova consulta", on_click=voltar_para_consulta)
