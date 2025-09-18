﻿# PowerShell script authored by Sean Metcalf (@PyroTek3)
# Original script date: 2025-09-12
#
# ---
# Modified by Kevin Pai (@Kevintw88)
# Modification date: 2025-09-18
# ---
#
# Script provided as-is

<#
.SYNOPSIS
    高效地稽核 Active Directory 中指定特權群組的所有成員及其屬性。
.DESCRIPTION
    此腳本可以遞迴地找出指定群組的所有成員 (包含使用者、電腦、服務帳戶和巢狀群組)，
    並一次性查詢它們的重要安全屬性，最後輸出成可供後續處理的物件。
.PARAMETER GroupName
    要查詢的 AD 群組名稱，預設為 'Domain Admins'。
    可指定其他群組，如 'Administrators', 'Enterprise Admins'。
.EXAMPLE
    .\Get-PrivilegedGroupMembers.ps1 -GroupName 'Enterprise Admins' | Format-Table
.EXAMPLE
    .\Get-PrivilegedGroupMembers.ps1 | Export-Csv -Path C:\temp\DomainAdmins.csv -NoTypeInformation
#>
Param (
    [string]$GroupName = 'Domain Admins',
    [string]$Domain = $env:userdnsdomain
)

# --- 1. 初始化與連線 (加入錯誤處理與目標DC指定) ---
Write-Host "正在連接到網域 $Domain 的 Domain Controller..."
try {
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain -Writable -ErrorAction Stop).Name
    Write-Host "成功連接到 DC: $DomainDC" -ForegroundColor Green
}
catch {
    Write-Host "錯誤: 無法找到可寫入的 Domain Controller。腳本中止。" -ForegroundColor Red
    return
}

# --- 2. 一次性獲取所有成員 (包含巢狀群組) ---
Write-Host "正在遞迴查詢群組 '$GroupName' 的所有成員..."
try {
    # Get-ADGroupMember 會傳回 ADPrincipal 物件，我們只需要他們的 DN
    $members = Get-ADGroupMember -Identity $GroupName -Recursive -Server $DomainDC -ErrorAction Stop
    if (-not $members) {
        Write-Host "群組 '$GroupName' 為空或不存在。" -ForegroundColor Yellow
        return
    }
}
catch {
    Write-Host "錯誤: 無法查詢群組 '$GroupName'。請檢查群組名稱或執行權限。" -ForegroundColor Red
    return
}


# --- 3. 高效批次查詢屬性 (核心改善) ---
# 定義我們真正需要的屬性，避免使用 '*'
$requiredProperties = @(
    'objectClass', 'SamAccountName', 'PasswordLastSet', 'LastLogonDate', 'Enabled', 
    'msDS-ResultantPSO', # 用於判斷細緻化密碼原則
    'userAccountControl', # 包含多個安全標誌
    'ServicePrincipalName', 'info', 'description'
)

Write-Host "正在從 $($members.Count) 個成員中批次獲取屬性..."
# 使用 Get-ADObject 一次性處理所有物件，無論其類型
$memberDetails = Get-ADObject -Identity $members.DistinguishedName -Properties $requiredProperties -Server $DomainDC

# --- 4. 處理與輸出物件 (取代 Format-Table) ---
# 將 userAccountControl 的值轉換成易於理解的屬性
$outputObjects = $memberDetails | Select-Object SamAccountName, objectClass, PasswordLastSet, LastLogonDate, Enabled, ServicePrincipalName, info, description, @{
    Name = 'PasswordNeverExpires'; Expression = { ($_.userAccountControl -band 0x10000) -ne 0 }
}, @{
    Name = 'DoesNotRequirePreAuth'; Expression = { ($_.userAccountControl -band 0x400000) -ne 0 }
}

# 輸出結果物件，讓使用者決定如何呈現
Write-Host "查詢完成。腳本已輸出 $($outputObjects.Count) 個物件。" -ForegroundColor Green
$outputObjects | Sort-Object SamAccountName