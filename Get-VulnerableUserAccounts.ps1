# PowerShell script authored by Sean Metcalf (@PyroTek3)
# Original script date: 2025-09-12
#
# ---
# Modified by Kevin Pai (@Kevintw88)
# Modification date: 2025-09-18
# ---
#
# Script provided as-is
Param (
    [string]$Domain = $env:userdnsdomain,
    [int]$InactiveDays = 180
)

# --- 1. 初始化與連線 (加入錯誤處理) ---
Write-Host "正在連接到網域 $Domain 的 Domain Controller..."
try {
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain -Writable -ErrorAction Stop).Name
    Write-Host "成功連接到 DC: $DomainDC" -ForegroundColor Green
}
catch {
    Write-Host "無法找到可寫入的 Domain Controller，腳本中止。" -ForegroundColor Red
    return
}

# --- 2. 設定變數與閾值 ---
$InactiveThresholdDate = (Get-Date).AddDays(-$InactiveDays)

# 定義要查詢的屬性，移除重複並加入所需屬性
$ADProperties = @(
    "Name", "Enabled", "SAMAccountname", "DisplayName", "LastLogonDate", "PasswordLastSet",
    "PasswordNeverExpires", "PasswordNotRequired", "PasswordExpired", "AccountExpirationDate",
    "AdminCount", "Created", "Modified", "CanonicalName", "DistinguishedName",
    "ServicePrincipalName", "SIDHistory", "UserAccountControl", "MemberOf"
)

# --- 3. 獲取資料 ---
Write-Host "正在從 AD 獲取所有使用者資料，可能需要一些時間..."
$AllUsers = Get-ADUser -Filter * -Properties $ADProperties -Server $DomainDC
$EnabledUsers = $AllUsers | Where-Object { $_.Enabled -eq $True }

# --- 4. 分析資料 (篩選應基於 EnabledUsers) ---
$InactiveUsers = $EnabledUsers | Where-Object { 
    ($_.LastLogonDate -le $InactiveThresholdDate) -and ($_.PasswordLastSet -le $InactiveThresholdDate) 
}
$ReversibleEncryptionUsers = $EnabledUsers | Where-Object { $_.UserAccountControl -band 0x0080 }
$PasswordNotRequiredUsers = $EnabledUsers | Where-Object { $_.PasswordNotRequired -eq $True }
$PasswordNeverExpiresUsers = $EnabledUsers | Where-Object { $_.PasswordNeverExpires -eq $True }
$NoPreAuthUsers = $EnabledUsers | Where-Object { $_.UserAccountControl -band 0x400000 } # UF_DONT_REQUIRE_PREAUTH flag
$UsersWithSIDHistory = $EnabledUsers | Where-Object { $_.SIDHistory -ne $null }
$UsersWithAdminCount = $EnabledUsers | Where-Object { $_.AdminCount -eq 1 }

# (新增) 檢查特權群組成員
$PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins")
$PrivilegedUsers = @()
foreach ($group in $PrivilegedGroups) {
    $PrivilegedUsers += Get-ADGroupMember -Identity $group -Server $DomainDC | Where-Object { $_.objectClass -eq 'user' }
}
# 取得唯一的使用者列表
$UniquePrivilegedUsers = $PrivilegedUsers | Sort-Object -Property DistinguishedName -Unique


# --- 5. 產生報告物件 (使用 PSCustomObject) ---
$Report = [PSCustomObject]@{
    "報告生成時間" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "目標網域" = $Domain
    "總使用者數" = $AllUsers.Count
    "已啟用使用者數" = $EnabledUsers.Count
    "--- 風險項目計數 ---" = "--- Count ---"
    "閒置帳戶 (超過 $($InactiveDays) 天)" = $InactiveUsers.Count
    "啟用可逆加密" = $ReversibleEncryptionUsers.Count
    "密碼為非必要" = $PasswordNotRequiredUsers.Count
    "密碼永不過期" = $PasswordNeverExpiresUsers.Count
    "不需 Kerberos 預先驗證" = $NoPreAuthUsers.Count
    "具有 SID History" = $UsersWithSIDHistory.Count
    "具有 AdminCount 屬性" = $UsersWithAdminCount.Count
    "特權群組成員數" = $UniquePrivilegedUsers.Count
    "--- 詳細資料 (建議匯出) ---" = "--- Details (Export Recommended) ---"
    "閒置帳戶列表" = $InactiveUsers.SamAccountName
    "特權帳戶列表" = $UniquePrivilegedUsers.SamAccountName
}

# --- 6. 輸出結果 ---
Write-Host "`n---------- AD 使用者帳戶安全報告摘要 ----------" -ForegroundColor Yellow
$Report | Format-List
Write-Host "------------------------------------------------" -ForegroundColor Yellow

# 提示如何匯出詳細資料
Write-Host "`n若要取得詳細報告，可將特定變數匯出成 CSV，例如：" -ForegroundColor Cyan
Write-Host '$InactiveUsers | Select-Object SamAccountName, DistinguishedName, LastLogonDate | Export-Csv -Path .\InactiveUsers.csv -NoTypeInformation'
Write-Host '$PasswordNeverExpiresUsers | Select-Object SamAccountName, DistinguishedName | Export-Csv -Path .\PwdNeverExpires.csv -NoTypeInformation'