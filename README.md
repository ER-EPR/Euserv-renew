# cmcloudflare
混淆worker代码

https://addressesapi.090227.xyz/CloudFlareYes
德雞續期專用腳本，實現自動續期，需自有VPS、德雞信箱要是GMAIL
僅支援TGBOT通知
5分鐘設定
輕鬆完成德雞續期
2022/05/04 更新
因Euserv PIN code寄信主旨改為以下兩種，且Euserv平常也不會寄信來，故關鍵詞改為EUserv 若有會寫Python篩選式且不用過多行代碼的可以在Pull request提出(因程式訴求為盡量精簡) EUserv - PIN for the Confirmation of a Security Check EUserv - Attempted Login

TRUECAPTCHA限額
下面兩項因TRUECAPTCHA每日100次觸發限額，建議修改為自己的
TRUECAPTCHA_USERID = os.environ.get("TRUECAPTCHA_USERID", "euextend")
TRUECAPTCHA_APIKEY = os.environ.get("TRUECAPTCHA_APIKEY", "deJhWBaqgd6QDN4BqJGf")
需要修改項目
下面四項需要修改為自己的
TG_BOT_TOKEN = '你的TG_BOT_TOKEN' TG_USER_ID = '你的TG_USER_ID'

USERNAME = os.environ.get("EUSERV_USERNAME", "你的德雞用戶名")
PASSWORD = os.environ.get("EUSERV_PASSWORD", "你的德雞密碼")

前置工作
請到Telegram找Bot Father申請一個機器人
[Bot Father] https://t.me/BotFather 並複製Bot Token
[複製Telegram ID] https://t.me/userinfobot
步驟1
# [取得Gmail IMAP] 
Prerequisites
Enable 2-Step Verification: You must have 2-Step Verification turned on; otherwise, the "App Passwords" option will not appear.
IMAP Access: Ensure IMAP is enabled in your Gmail Settings under the Forwarding and POP/IMAP tab. 
How to Create the App Password
Go to your Google Account Security Settings.
Scroll down to the "How you sign in to Google" section and select 2-Step Verification.
Scroll to the very bottom and click on App passwords.
Tip: If you can't find it, use the search bar at the top of the Google Account page and type "App passwords".
Enter a custom name for the app (e.g., "Server Email Sync") and click Create.
Google will display a 16-character code. This is your IMAP password.
# 创建secret：
GMAIL_ADDRESS
GMAIL_APP_PASSWORD
# 將eu.py排入定時任務
 crontab -e  

 0 1 * * * /usr/bin/python3 /root/eu.py  
0 1 * * * 定義為每天0點1分執行，可自行修改為對應時間，/root/eu.py請改為eu.py所在路徑

依序按下Ctrl+X、Y、Enter
crontab -l  
crontab -l是為了查看是否有成功設定crontab

續期成功
image

歡迎多多STAR我的項目
若是執行上有什麼問題
請透過issue提出
錯誤解決
當出現下方圖片錯誤，代表gmail token過期了，只要重新執行4-4獲取token並替換舊token即可 image
