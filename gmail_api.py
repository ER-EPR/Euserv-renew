import os
import sys
import time
import re
import json
import traceback
from datetime import datetime

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google.auth.exceptions import RefreshError, TransportError

import os, requests, socks, socket
socks.set_default_proxy()
socket.socket = socks.socksocket

dir_name = os.path.dirname(os.path.abspath(__file__)) + os.sep
os.chdir(dir_name)

SCOPES = ['https://mail.google.com/']

def log_api(msg):
    """统一日志输出"""
    print(f"[Gmail API] {msg}")

def gmail_authenticate(userId):
    """
    Gmail API 认证函数
    支持自动刷新 + 失败恢复
    """
    creds = None
    token_file = f'token_{userId}.json'
    
    log_api(f"开始认证用户: {userId}")
    log_api(f"Token 文件: {token_file}")
    
    # 检查 token 文件是否存在
    if os.path.exists(token_file):
        log_api("✓ 找到 Token 文件，尝试加载...")
        try:
            creds = Credentials.from_authorized_user_file(token_file, SCOPES)
            log_api(f"Token 状态 - 有效: {creds.valid}, 过期: {creds.expired if creds else 'N/A'}")
        except Exception as e:
            log_api(f"✗ Token 文件损坏: {str(e)}")
            log_api("→ 将删除并重新生成")
            try:
                os.remove(token_file)
                log_api("✓ 已删除损坏的 Token 文件")
            except:
                pass
            creds = None
    else:
        log_api("⚠ 未找到 Token 文件")
    
    # 如果没有有效凭据，尝试刷新或重新认证
    if not creds or not creds.valid:
        log_api("Token 无效/过期，尝试刷新或重新认证...")
        
        # 情况1: 有 refresh_token，尝试刷新
        if creds and creds.expired and creds.refresh_token:
            log_api("→ 尝试使用 refresh_token 刷新...")
            try:
                creds.refresh(Request())
                log_api("✓ Token 刷新成功！")
                
                # 保存新 token
                with open(token_file, "w") as token:
                    token.write(creds.to_json())
                log_api(f"✓ 已保存新 Token 到 {token_file}")
                
            except RefreshError as e:
                error_msg = str(e)
                log_api(f"✗ Refresh 失败: {error_msg}")
                
                # 判断错误类型
                if 'invalid_grant' in error_msg.lower():
                    log_api("🔑 错误: Refresh Token 已失效或被撤销")
                    log_api("💡 可能原因:")
                    log_api("   1. Google OAuth 同意屏幕未设置为'生产'模式（测试模式仅7天有效）")
                    log_api("   2. 用户手动撤销了应用权限")
                    log_api("   3. Refresh Token 超过6个月未使用（Google 策略）")
                    log_api("   4. 凭据文件 (credentials.json) 已更换")
                
                # 删除无效的 token 文件
                if os.path.exists(token_file):
                    try:
                        os.remove(token_file)
                        log_api(f"✓ 已删除无效的 Token 文件: {token_file}")
                    except Exception as del_err:
                        log_api(f"⚠ 删除 Token 失败: {del_err}")
                
                # 尝试从环境变量恢复
                creds = try_restore_from_env(userId, token_file)
                
                if not creds:
                    # 无法自动恢复，抛出明确异常
                    raise Exception(
                        f"\n{'='*60}\n"
                        f"🔑 Gmail API 认证失败 - 需要手动重新授权！\n"
                        f"{'='*60}\n"
                        f"用户: {userId}\n"
                        f"Token 文件: {token_file}\n\n"
                        f"🔧 恢复步骤:\n"
                        f"  1️⃣  本地运行以下命令重新生成 Token:\n"
                        f"      python gmail_api.py {userId}\n\n"
                        f"  2️⃣  将生成的 {token_file} 上传到服务器/CI环境:\n"
                        f"      scp {token_file} user@server:/path/to/project/\n\n"
                        f"  3️⃣  或者通过环境变量注入 (推荐 CI/CD):\n"
                        f"      export GMAIL_TOKEN_{userId.replace('@', '_').replace('.', '_')}='{{...}}'\n\n"
                        f"📝 详细错误:\n{traceback.format_exc()}\n"
                        f"{'='*60}\n"
                    )
                    
            except Exception as e:
                log_api(f"✗ 刷新过程异常: {str(e)}")
                log_api(traceback.format_exc())
                raise
                
        # 情况2: 没有 refresh_token 或刷新失败，需要重新认证
        else:
            log_api("→ 没有有效的 Refresh Token，需要重新认证")
            
            # 优先尝试从环境变量恢复
            creds = try_restore_from_env(userId, token_file)
            
            if not creds:
                log_api("⚠ 无法自动恢复，需要交互式认证")
                log_api("💡 提示: 在自动化环境 (如 GitHub Actions) 中，")
                log_api("   请通过环境变量 GMAIL_TOKEN_{userId} 注入 Token")
                
                # 检查是否在交互式环境
                if sys.stdin.isatty():
                    log_api("→ 检测到交互式终端，启动本地服务器认证...")
                    try:
                        flow = InstalledAppFlow.from_client_secrets_file(
                            'credentials.json', SCOPES)
                        creds = flow.run_local_server(port=36666)
                        
                        # 保存 token
                        with open(token_file, "w") as token:
                            token.write(creds.to_json())
                        log_api(f"✓ 认证成功！Token 已保存到 {token_file}")
                        
                    except Exception as e:
                        log_api(f"✗ 交互式认证失败: {str(e)}")
                        raise
                else:
                    raise Exception(
                        f"\n{'='*60}\n"
                        f"⚠ 非交互式环境 - 无法进行 OAuth 授权\n"
                        f"{'='*60}\n"
                        f"用户: {userId}\n\n"
                        f"🔧 解决方案:\n"
                        f"  方案1: 通过环境变量注入 Token\n"
                        f"      export GMAIL_TOKEN_{userId.replace('@', '_').replace('.', '_')}='$(cat token_{userId}.json)'\n\n"
                        f"  方案2: 在本地生成 Token 后上传到服务器:\n"
                        f"      python gmail_api.py {userId}\n"
                        f"      scp token_{userId}.json user@server:/path/to/project/\n\n"
                        f"  方案3: 使用 GitHub Secrets (GitHub Actions):\n"
                        f"      secrets.GMAIL_TOKEN_{userId.replace('@', '_').replace('.', '_')}\n"
                        f"{'='*60}\n"
                    )
    
    # 构建 Gmail 服务
    try:
        service = build('gmail', 'v1', credentials=creds)
        log_api("✓ Gmail API 服务构建成功")
        return service
    except Exception as e:
        log_api(f"✗ 构建 Gmail 服务失败: {str(e)}")
        raise

def try_restore_from_env(userId, token_file):
    """
    尝试从环境变量恢复 Token
    环境变量格式: GMAIL_TOKEN_username_gmail_com
    """
    env_key = f"GMAIL_TOKEN_{userId.replace('@', '_').replace('.', '_')}"
    token_json = os.environ.get(env_key)
    
    if token_json:
        log_api(f"→ 从环境变量 {env_key} 恢复 Token...")
        try:
            # 解析 JSON
            token_data = json.loads(token_json)
            
            # 创建 Credentials
            creds = Credentials.from_authorized_user_info(token_data, SCOPES)
            
            # 验证有效性
            if creds and creds.valid:
                log_api("✓ 环境变量 Token 有效")
                
                # 可选：保存到文件（便于调试）
                try:
                    with open(token_file, "w") as f:
                        f.write(token_json)
                    log_api(f"✓ 已保存环境变量 Token 到 {token_file}")
                except:
                    pass
                    
                return creds
            elif creds and creds.expired and creds.refresh_token:
                # 尝试刷新
                log_api("→ Token 已过期，尝试刷新...")
                try:
                    creds.refresh(Request())
                    log_api("✓ Token 刷新成功")
                    
                    # 保存刷新后的 token
                    with open(token_file, "w") as f:
                        f.write(creds.to_json())
                    
                    return creds
                except Exception as e:
                    log_api(f"✗ 刷新失败: {str(e)}")
                    return None
            else:
                log_api("⚠ 环境变量 Token 无效")
                return None
                
        except Exception as e:
            log_api(f"✗ 环境变量 Token 解析失败: {str(e)}")
            return None
    else:
        log_api(f"→ 环境变量 {env_key} 未设置")
    
    return None

def search_messages(service, query):
    """搜索邮件"""
    try:
        result = service.users().messages().list(userId='me', q=query).execute()
        messages = []
        if 'messages' in result:
            messages.extend(result['messages'])
        while 'nextPageToken' in result:
            page_token = result['nextPageToken']
            result = service.users().messages().list(
                userId='me', q=query, pageToken=page_token).execute()
            if 'messages' in result:
                messages.extend(result['messages'])
        log_api(f"搜索 '{query}' → 找到 {len(messages)} 封邮件")
        return messages
    except Exception as e:
        log_api(f"搜索邮件失败: {str(e)}")
        raise

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python gmail_api.py <email1> [email2] ...")
        sys.exit(1)
    
    emails = sys.argv[1:]
    print(f"\n🔐 Gmail API 交互式认证工具")
    print(f"{'='*50}")
    
    for email in emails:
        print(f"\n📧 处理用户: {email}")
        print("-" * 50)
        try:
            service = gmail_authenticate(email)
            print(f"✓ 认证成功！")
            
            # 测试：获取最近的邮件
            print(f"📝 测试: 获取收件箱最近的邮件...")
            results = search_messages(service, "in:inbox")
            print(f"   收件箱邮件数量: {len(results)}")
            
        except Exception as e:
            print(f"✗ 认证失败: {str(e)}")
            sys.exit(1)
    
    print(f"\n{'='*50}")
    print("✅ 所有用户认证完成！")
    print(f"Token 已保存到对应文件。")
