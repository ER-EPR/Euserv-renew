#! /usr/bin/env python3

import os
import re
import json
import time
import base64

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP_SSL, SMTPDataError

import requests
from bs4 import BeautifulSoup
from base64 import urlsafe_b64decode
from gmail_api import *
import io
from PIL import Image

dir_name = os.path.dirname(os.path.abspath(__file__)) + os.sep
os.chdir(dir_name)

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "你的TG_BOT_TOKEN")
TG_USER_ID = os.environ.get("TG_USER_ID", "你的TG_USER_ID")
TG_API_HOST = os.environ.get("TG_API_HOST", "api.telegram.org")

# 多個帳戶請使用空格隔開
USERNAME = os.environ.get("EUSERV_USERNAME", "你的德雞用戶名")  
PASSWORD = os.environ.get("EUSERV_PASSWORD", "你的德雞密碼") 

TRUECAPTCHA_USERID = os.environ.get("TRUECAPTCHA_USERID", "euextend")
TRUECAPTCHA_APIKEY = os.environ.get("TRUECAPTCHA_APIKEY", "deJhWBaqgd6QDN4BqJGf")

PIN_KEY_WORD = 'EUserv'

# Maximum number of login retry
LOGIN_MAX_RETRY_COUNT = 5


# options: True or False
TRUECAPTCHA_CHECK_USAGE = False


user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/99.0.4844.51 Safari/537.36"
)
desp = ""  # 空值

unixTimeToDate = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))

def log(info: str):
    print(info)
    global desp
    desp = desp + info + "\n"


def login_retry(*args, **kwargs):
    def wrapper(func):
        def inner(username, password):
            max_retry = kwargs.get("max_retry")
            # default retry 3 times
            if not max_retry:
                max_retry = 3
            number = 0
            while number < max_retry:
                try:
                    number += 1
                    if number > 1:
                        log("[EUserv] Login tried the {}th time".format(number))
                    sess_id, session = func(username, password)
                    if sess_id != "-1":
                        return sess_id, session
                    else:
                        if number == max_retry:
                            return sess_id, session
                except BaseException as e:
                    log(str(e))
            else:
                return None, None
        return inner
    return wrapper


def captcha_solver(captcha_image_url: str, session: requests.session) -> dict:
    """
    使用视觉模型或OCR API替换TrueCaptcha API来识别验证码
    支持OpenAI GPT-4 Vision或阿里云通义千问视觉模型
    """
    # 获取验证码图片
    response = session.get(captcha_image_url)
    
    # 将图片转换为base64格式
    image_bytes = response.content
    
    # 方案1: 使用阿里云通义千问视觉API (推荐)
    try:
        result = solve_captcha_with_qwen_vision(image_bytes)
        if result and "error" not in str(result).lower():
            if isinstance(result, str):
                return {"result": result}
            else:
                return result
    except Exception as e:
        print(f"Qwen Vision API failed: {e}")
    
    # 方案2: 使用OpenAI GPT-4 Vision API (如果可用)
    try:
        result = solve_captcha_with_openai_vision(image_bytes)
        if result and "error" not in str(result).lower():
            if isinstance(result, str):
                return {"result": result}
            else:
                return result
    except Exception as e:
        print(f"OpenAI Vision API failed: {e}")
    
    # 方案3: 使用本地OCR (Tesseract) 作为备选
#    try:
#        result = solve_captcha_with_tesseract(image_bytes)
#        if result:
#            return {"result": result}
#    except Exception as e:
#        print(f"Tesseract OCR failed: {e}")
    
    # 如果所有方法都失败，返回错误信息
    return {"error": "All captcha solving methods failed"}

def solve_captcha_with_qwen_vision(image_bytes):
    """
    使用阿里云通义千问视觉API识别验证码 (OpenAI兼容接口)
    需要设置以下环境变量:
    - QWEN_API_KEY: 通义千问API密钥
    - QWEN_BASE_URL: 通义千问API基础URL (可选，默认为阿里云地址)
    """
    import openai
    
    api_key = os.getenv("QWEN_API_KEY")
    if not api_key:
        raise Exception("QWEN_API_KEY not set")
    
    # 设置基础URL，默认为阿里云通义千问API地址
    base_url = os.getenv("QWEN_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    
    # 将图片转换为base64用于发送到API
    image_base64 = base64.b64encode(image_bytes).decode()
    
    # 创建OpenAI客户端，使用阿里云兼容接口
    client = openai.OpenAI(
        api_key=api_key,
        base_url=base_url
    )
    
    response = client.chat.completions.create(
        model="qwen-vl-max",  # 或使用 qwen-vl-plus，根据需要选择
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "This is a captcha image. Extract the text characters from the image. Only respond with the text characters, nothing else. Do not add any explanations or additional text."},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{image_base64}"
                        }
                    }
                ]
            }
        ],
        max_tokens=20,
        temperature=0.1  # 低温度以获得更准确的识别结果
    )
    
    text_result = response.choices[0].message.content.strip()
    
    # 有时候API可能返回额外的解释文本，我们只需要验证码文本
    # 简单清理可能的多余文本
    lines = text_result.split('\n')
    for line in lines:
        line = line.strip()
        # 假设验证码是较短的纯字母数字组合
        if len(line) >= 2 and len(line) <= 10 and line.replace(' ', '').isalnum():
            return line
    
    # 如果没有找到合适的验证码格式，返回第一行内容
    return lines[0].strip() if lines else text_result

def solve_captcha_with_openai_vision(image_bytes):
    """
    使用OpenAI GPT-4 Vision API识别验证码
    需要设置OPENAI_API_KEY环境变量
    """
    import openai
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise Exception("OPENAI_API_KEY not set")
    
    # 将图片转换为base64用于发送到API
    image_base64 = base64.b64encode(image_bytes).decode()
    
    client = openai.OpenAI(api_key=api_key)
    
    response = client.chat.completions.create(
        model="gpt-4-vision-preview",
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "This is a captcha image. Extract the text characters from the image. Only respond with the text, nothing else."},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{image_base64}"
                        }
                    }
                ]
            }
        ],
        max_tokens=30,
        temperature=0.1
    )
    
    text_result = response.choices[0].message.content.strip()
    return text_result

def preprocess_captcha_image(image_bytes):
    """
    预处理验证码图片以提高识别准确性
    """
    from PIL import Image
    import cv2
    import numpy as np
    
    # 使用OpenCV进行图像预处理
    image = Image.open(io.BytesIO(image_bytes))
    image_np = np.array(image)
    
    # 转换为灰度图
    gray = cv2.cvtColor(image_np, cv2.COLOR_BGR2GRAY)
    
    # 应用高斯模糊去除噪声
    blur = cv2.GaussianBlur(gray, (5, 5), 0)
    
    # 应用阈值处理
    _, thresh = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    
    # 转换回PIL格式
    processed_image = Image.fromarray(thresh)
    
    # 保存到字节流
    img_byte_arr = io.BytesIO()
    processed_image.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    
    return img_byte_arr

def handle_captcha_solved_result(solved: dict) -> str:
    """Since CAPTCHA sometimes appears as a very simple binary arithmetic expression.
    But since recognition sometimes doesn't show the result of the calculation directly,
    that's what this function is for.
    """
    if "result" in solved:
        solved_text = str(solved["result"])
        if "RESULT  IS" in solved_text:
            log("[Captcha Solver] You are using the demo apikey.")
            print("There is no guarantee that demo apikey will work in the future!")
            # because using demo apikey
            text = re.findall(r"RESULT  IS . (.*) .", solved_text)[0]
        else:
            # using your own apikey
            log("[Captcha Solver] You are using your own apikey.")
            text = solved_text
        operators = ["X", "x", "+", "-"]
        if any(x in text for x in operators):
            for operator in operators:
                operator_pos = text.find(operator)
                if operator == "x" or operator == "X":
                    operator = "*"
                if operator_pos != -1:
                    left_part = text[:operator_pos]
                    right_part = text[operator_pos + 1 :]
                    if left_part.isdigit() and right_part.isdigit():
                        return eval(
                            "{left} {operator} {right}".format(
                                left=left_part, operator=operator, right=right_part
                            )
                        )
                    else:
                        # Because these symbols("X", "x", "+", "-") do not appear at the same time,
                        # it just contains an arithmetic symbol.
                        return text
        else:
            return text
    else:
        print(solved)
        raise KeyError("Failed to find parsed results.")


def get_captcha_solver_usage() -> dict:
    url = "https://api.apitruecaptcha.org/one/getusage"

    params = {
        "username": TRUECAPTCHA_USERID,
        "apikey": TRUECAPTCHA_APIKEY,
    }
    r = requests.get(url=url, params=params)
    j = json.loads(r.text)
    return j


@login_retry(max_retry=LOGIN_MAX_RETRY_COUNT)
def login(username: str, password: str) -> (str, requests.session):
    headers = {"user-agent": user_agent, "origin": "https://www.euserv.com"}
    url = "https://support.euserv.com/index.iphp"
    captcha_image_url = "https://support.euserv.com/securimage_show.php"
    session = requests.Session()

    sess = session.get(url, headers=headers)
    sess_id = re.findall("PHPSESSID=(\\w{10,100});", str(sess.headers))[0]
    # visit png
    logo_png_url = "https://support.euserv.com/pic/logo_small.png"
    session.get(logo_png_url, headers=headers)

    login_data = {
        "email": username,
        "password": password,
        "form_selected_language": "en",
        "Submit": "Login",
        "subaction": "login",
        "sess_id": sess_id,
    }
    r = session.post(url, headers=headers, data=login_data)
    r.raise_for_status()

    if (
        r.text.find("Hello") == -1
        and r.text.find("Confirm or change your customer data here") == -1
    ):
        if "To finish the login process please solve the following captcha." in r.text:
            log("[Captcha Solver] 進行驗證碼識別...")
            solved_result = captcha_solver(captcha_image_url, session)
            if not "result" in solved_result:
                print(solved_result)
                raise KeyError("Failed to find parsed results.")
            captcha_code = handle_captcha_solved_result(solved_result)
            log("[Captcha Solver] 識別的驗證碼是: {}".format(captcha_code))

            if TRUECAPTCHA_CHECK_USAGE:
                usage = get_captcha_solver_usage()
                log(
                    "[Captcha Solver] current date {0} api usage count: {1}".format(
                        usage[0]["date"], usage[0]["count"]
                    )
                )

            r = session.post(
                url,
                headers=headers,
                data={
                    "subaction": "login",
                    "sess_id": sess_id,
                    "captcha_code": captcha_code,
                },
            )
            if (
                r.text.find(
                    "To finish the login process please solve the following captcha."
                )
                == -1
            ):
                log("[Captcha Solver] 驗證通過,登录消息：{}".format(r.text))
                
            else:
                log("[Captcha Solver] 驗證失敗")
                return "-1", session

        # 改进的PIN码检测逻辑 - 使用更全面的检测条件
        if ('PIN sent to' in r.text or 
            'Enter PIN' in r.text or 
            'kc2_security_password_dialog' in r.text or
            'name="auth"' in r.text or  # 检查是否有PIN输入框
            'auth' in r.text or  # 检查是否有auth字段
            'pin' in r.text.lower()):  # 检查是否有pin相关字段
            log("[Login] 检测到需要输入PIN码")
            request_time = time.time()
            
            # 尝试从页面中提取c_id
            c_id_re = re.search(r'c_id["\']?\s*value["\']?=["\']([^"\']*)["\']', r.text)
            c_id = c_id_re.group(1) if c_id_re else None
            
            # 尝试从页面中提取sess_id（如果在表单中有隐藏字段）
            sess_id_re = re.search(r'sess_id["\']?\s*value["\']?=["\']([^"\']*)["\']', r.text)
            if sess_id_re:
                sess_id = sess_id_re.group(1)
            
            pin_code = wait_for_email(request_time)
            log("[Email PIN Solver] 驗證碼是: {}".format(pin_code))
            # 严格校验：必须是非空字符串
            if not pin_code or not isinstance(pin_code, str) or not pin_code.strip():
                log("[Email PIN Solver] ❌ 无效 PIN（空值/非字符串），终止登录")
                return "-1", session
            pin_code = pin_code.strip()
            log(f"[Email PIN Solver] ✅ 使用 PIN: {pin_code}")
                        
            payload = {
                "pin": pin_code,
                "auth": pin_code,  # 尝试使用auth字段
                "Submit": "Confirm",
                "subaction": "login",
                "sess_id": sess_id,
                "c_id": c_id,
            }
            # 尝试登录
            r = session.post(url, headers=headers, data=payload)
            
            # 检查登录是否成功
            if 'Logout</a>' in r.text or 'logout' in r.text.lower():
                log("[Email PIN Solver] PIN验证成功")
                return sess_id, session
            elif 'To finish the login process please solve the following captcha.' in r.text:
                log("[Email PIN Solver] 需要重新进行验证码验证")
                return "-1", session
            else:
                log("[Email PIN Solver] PIN验证失败，页面内容: {}".format(r.text[:500]))
                return "-1", session
        # 如果既没有 PIN 请求，页面又有登录成功的特征
        if 'Logout</a>' in r.text or 'Hello' in r.text:
            return sess_id, session
        # 如果页面包含登录表单但未成功登录，可能需要进一步分析
        if 'password' in r.text.lower() and 'login' in r.text.lower():
            log("[Login] 检测到登录表单，可能需要重新登录")
            return "-1", session
        
        # 添加更详细的调试信息
        log("[Login] 登录失败，无法识别的页面状态。页面包含的关键信息:")
        if 'error' in r.text.lower():
            log("[Login] 页面包含错误信息")
        if 'security' in r.text.lower():
            log("[Login] 页面包含安全相关提示")
        if 'verify' in r.text.lower():
            log("[Login] 页面包含验证相关提示")
        if 'confirm' in r.text.lower():
            log("[Login] 页面包含确认相关提示")
        
        log("[Login] 登录失败，无法识别的页面状态: {}".format(r.text[:500]))
        return "-1", session
    else:
        log("[Login] 登录成功")
        return sess_id, session


def get_servers(sess_id: str, session: requests.session) -> {}:
    d = {}
    url = "https://support.euserv.com/index.iphp?sess_id=" + sess_id
    headers = {"user-agent": user_agent, "origin": "https://www.euserv.com"}
    r = session.get(url=url, headers=headers)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    for tr in soup.select(
        "#kc2_order_customer_orders_tab_content_1 .kc2_order_table.kc2_content_table tr"
    ):
        server_id = tr.select(".td-z1-sp1-kc")
        if not len(server_id) == 1:
            continue
        flag = (
            True
            if tr.select(".td-z1-sp2-kc .kc2_order_action_container")[0]
            .get_text()
            .find("Contract extension possible from")
            == -1
            else False
        )
        d[server_id[0].get_text()] = flag
    return d


def get_verification_code(service, email_id, request_time):
    try:
        email = service.users().messages().get(userId='me', id=email_id['id']).execute()
        internal_date = float(email.get("internalDate", 0)) / 1000
        subject = next((h['value'] for h in email['payload']['headers'] if h['name'] == 'Subject'), 'N/A')
        
        if internal_date <= request_time - 8:
            log(f"[Email] 邮件时间过早（主题: {subject}），跳过")
            return None
        
        # 提取邮件正文
        if email['payload'].get('body', {}).get('size'):
            data = urlsafe_b64decode(email['payload']['body']['data']).decode(errors='ignore')
        else:
            parts = email['payload'].get('parts', [])
            data = urlsafe_b64decode(parts[0]['body']['data']).decode(errors='ignore') if parts else ""
        
        # 调试：记录邮件片段（脱敏）
        log(f"[Email] 解析邮件（主题: {subject}），内容前200字符: {data[:200]}")
        pin_match = re.search(r'PIN:\s*([A-Za-z0-9]{4,8})', data)  # 更健壮的正则
        if pin_match:
            return pin_match.group(1)
        log("[Email] 未匹配到 PIN 格式（检查正则表达式）")
        return None
    except Exception as e:
        log(f"[Email] 邮件解析异常: {str(e)}")
        return None

def wait_for_email(request_time):
    try:
        service = gmail_authenticate(userId=userId)
        start_wait = time.time()
        log(f"[Email] 开始监听邮箱（关键词: {PIN_KEY_WORD}），超时: 120s")
        
        while time.time() < request_time + 120:
            try:
                results = search_messages(service, PIN_KEY_WORD)
                log(f"[Email] 搜索结果数量: {len(results) if results else 0}")
                
                if results:
                    pin_code = get_verification_code(service, results[0], request_time)
                    if pin_code:
                        log(f"[Email] ✅ 成功提取 PIN: {pin_code}")
                        return pin_code
                    else:
                        log("[Email] ⚠️ 找到邮件但未解析出 PIN（检查正则/邮件格式）")
            except Exception as e:
                log(f"[Email] 搜索/解析邮件异常: {str(e)}")
            
            time.sleep(5)
        
        log(f"[Email] ❌ 超时（耗时 {time.time()-start_wait:.1f}s）：未收到含 PIN 的邮件")
        return None  # 明确返回 None 而非 False
        
    except Exception as e:
        import traceback
        err_str = str(e).lower()
        if "invalid_grant" in err_str:
            log("[Email] 🔑 Gmail API 认证失败！原因：OAuth 令牌过期/无效")
            log("[Email] 💡 解决方案：")
            log("   1. 删除 token.json（如有）")
            log("   2. 重新运行认证流程生成新令牌")
            log("   3. 检查环境变量 GOOGLE_APPLICATION_CREDENTIALS 是否正确")
        elif "unauthorized" in err_str or "401" in err_str:
            log("[Email] 🔑 Gmail API 权限不足，请检查 OAuth 范围配置")
        
        log(f"[Email] 堆栈跟踪:\n{traceback.format_exc()}")
        return None

def renew(
    sess_id: str, session: requests.session, password: str, order_id: str
) -> bool:
    url = "https://support.euserv.com/index.iphp"
    headers = {
        "user-agent": user_agent,
        "Host": "support.euserv.com",
        "origin": "https://support.euserv.com",
        "Referer": "https://support.euserv.com/index.iphp",
    }

    r = session.post(url, headers=headers, data={
        "Submit": "Extend contract",
        "sess_id": sess_id,
        "ord_no": order_id,
        "subaction": "choose_order",
        "show_contract_extension": "1",
        "choose_order_subaction": "show_contract_details",
    })

    r = session.post(url, headers=headers, data={
        "sess_id": sess_id,
        "subaction": "kc2_customer_contract_details_get_change_plan_dialog",
        "ord_id": order_id,
        "show_manual_extension_if_available": "1",
    })

    # send pin code
    request_time = time.time()
    log(f'[EUserv] Send pin code to {userId} Time: {unixTimeToDate(request_time)}')
    r = session.post(url, headers=headers, data={
        "sess_id": sess_id,
        "subaction": "show_kc2_security_password_dialog",
        "prefix":	"kc2_customer_contract_details_extend_contract_",
        "type":	"1",
    })
    if 'PIN sent to ***' in r.text or 'Enter PIN' in r.text or 'kc2_security_password_dialog_prompt' in r.text:
        log('[EUserv] A PIN has been sent to your email address')
    else:
        log("[EUserv] Send Email failed ! 返回消息：{}".format(r.text))
        return False
    
    pin_code = wait_for_email(request_time)
    log("[Email PIN Solver] 驗證碼是: {}".format(pin_code))
    if not pin_code: return False

    r = session.post(url, headers=headers, data={
        "auth": pin_code,
        "sess_id": sess_id,
        "subaction": "kc2_security_password_get_token",
        "prefix": "kc2_customer_contract_details_extend_contract_",
        "type": "1",
        "ident": "kc2_customer_contract_details_extend_contract_" + order_id,
    })
    if not r.json().get("rs") == "success":
        return False
    token = r.json().get('token').get('value')

    r = session.post(url, headers=headers, data={
        "sess_id": sess_id,
        "subaction": "kc2_customer_contract_details_get_extend_contract_confirmation_dialog",
        "token": token,
    })
    r = session.post(url, headers=headers, data={
        "sess_id": sess_id,
        "ord_id": order_id,
        "subaction": "kc2_customer_contract_details_extend_contract_term",
        "token": token,
    })

    time.sleep(5)
    return True


def check(sess_id: str, session: requests.session):
    print("Checking.......")
    d = get_servers(sess_id, session)
    flag = True
    for key, val in d.items():
        if val:
            flag = False
            log("[EUserv] ServerID: %s Renew Failed!" % key)

    if flag:
        log("[EUserv] ALL Work Done! Enjoy~")


def telegram():
    data = (
        ('chat_id', TG_USER_ID),
        ('text', 'EUserv續期日誌\n\n' + desp)
    )
    response = requests.post('https://' + TG_API_HOST + '/bot' + TG_BOT_TOKEN + '/sendMessage', data=data)
    if response.status_code != 200:
        print('Telegram Bot 推送失敗')
    else:
        print('Telegram Bot 推送成功')

if __name__ == "__main__":
    if not USERNAME or not PASSWORD:
        log("[EUserv] 你沒有新增任何賬戶")
        exit(1)
    user_list = USERNAME.strip().split()
    passwd_list = PASSWORD.strip().split()
    if len(user_list) != len(passwd_list):
        log("[EUserv] The number of usernames and passwords do not match!")
        exit(1)
    for i in range(len(user_list)):
        userId = user_list[i]
        log("*" * 30)
        log("[EUserv] 正在續期第 %d 個帳號 %s" % (i + 1, userId))
        sessid, s = login(user_list[i], passwd_list[i])
        if sessid == "-1":
            log("[EUserv] 第 %d 個帳號登入失敗，請檢查登入訊息" % (i + 1))
            continue
        elif not sessid:
            continue
        SERVERS = get_servers(sessid, s)
        log("[EUserv] 檢測到第 {} 個帳號有 {} 台 VPS，正在嘗試續期".format(i + 1, len(SERVERS)))
        for k, v in SERVERS.items():
            if v:
                if not renew(sessid, s, passwd_list[i], k):
                    log("[EUserv] ServerID: %s 德雞中彈倒地!" % k)
                else:
                    log("[EUserv] ServerID: %s 德雞續期成功!" % k)
            else:
                log("[EUserv] ServerID: %s 不須續期" % k)
        time.sleep(15)
        check(sessid, s)
        time.sleep(5)

    TG_BOT_TOKEN and TG_USER_ID and TG_API_HOST and telegram()
