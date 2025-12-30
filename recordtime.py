import json
import os
from datetime import datetime, timedelta

def get_last_run_file():
    """获取记录上次运行时间的文件路径"""
    return os.path.join(os.path.dirname(__file__), "last_run.json")

def record_successful_run():
    """记录本次成功运行的时间"""
    last_run_file = get_last_run_file()
    data = {
        "last_run": datetime.now().isoformat()
    }
    with open(last_run_file, 'w', encoding='utf-8') as f:
        json.dump(data, f)

def should_run_again():
    """检查距离上次成功运行是否已超过30天"""
    last_run_file = get_last_run_file()
    
    if not os.path.exists(last_run_file):
        # 如果没有记录文件，则允许运行
        return True, "首次运行"
    
    try:
        with open(last_run_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if "last_run" not in data:
            return True, "记录文件格式不正确"
        
        last_run_time = datetime.fromisoformat(data["last_run"])
        time_diff = datetime.now() - last_run_time
        days_diff = time_diff.days
        
        if days_diff >= 30:
            return True, f"距离上次运行已过 {days_diff} 天，可以运行"
        else:
            return False, f"距离上次运行仅 {days_diff} 天，跳过运行（需满30天）"
    
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        log(f"[EUserv] 读取运行记录失败: {e}")
        return True, "记录文件损坏，允许运行"

if __name__ == "__main__":
    # 检查是否应该运行
    should_run, reason = should_run_again()
    log(f"[EUserv] 运行检查: {reason}")
    
    if not should_run:
        log("[EUserv] 距离上次成功运行未满30天，跳过执行")
        exit(0)
    
    if not USERNAME or not PASSWORD:
        log("[EUserv] 你沒有新增任何賬戶")
        exit(1)
    user_list = USERNAME.strip().split()
    passwd_list = PASSWORD.strip().split()
    if len(user_list) != len(passwd_list):
        log("[EUserv] The number of usernames and passwords do not match!")
        exit(1)
    
    any_success = False  # 记录是否有任何一个账号成功续期
    
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
        any_success = True  # 标记至少有一个账号成功登录
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
    
    # 如果有任何一个账号成功续期，则记录运行时间
    if any_success:
        record_successful_run()
        log("[EUserv] 已记录本次成功运行时间，下次运行需等待30天")
    else:
        log("[EUserv] 所有账号均登录失败，未记录运行时间")
