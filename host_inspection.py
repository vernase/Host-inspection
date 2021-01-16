import os
import re
import psutil


def cpu():  # cpu使用率
    print('获取CPU信息...')
    cpu = 'CPU使用率：{}{}\n'.format(str(psutil.cpu_percent(1)), '%')
    return cpu


def mem():  # 内存使用率
    print('获取内存信息...')
    mem = '内存使用率：{}{}\n'.format(str(psutil.virtual_memory()[2]), '%')
    return mem


def disk():  # 磁盘使用率
    print('获取磁盘信息...')
    disk = '磁盘使用率：{}{}'.format(psutil.disk_usage('/')[3], '%')
    return disk


def account():  # 本地账户检查
    print('检查本地账户情况...')
    admin_info = os.popen('net localgroup administrators').read()
    administrators = re.findall(r'-\n(.+?)命令成功完成', admin_info, re.S)[0]  # 管理组
    users_info = os.popen('net localgroup users').read()
    users = re.findall(r'-\n(.+?)命令成功完成', users_info, re.S)[0]  # 用户组
    guest_info = os.popen('net user guest').read()
    guest = re.findall(r'帐户启用(.+?)帐户到期', guest_info, re.S)[0].replace(' ', '').replace('\n', '')  # guest账户是否禁止
    if guest == 'No':
        guest_able = 'guest账户已禁用'
    elif guest == 'Yes':
        guest_able = '注意，guest账户未禁用！'
    account = '管理组：\n{}\n用户组：\n{}\n{}'.format(administrators, users, guest_able)
    return account


def tasklist():  # 获取进程列表
    print('获取进程列表...')
    tasklist = os.popen('tasklist').read()
    return tasklist


def service():  # 获取已启用的服务
    print('获取服务列表...')
    service = os.popen('net start').read()
    return service


def schtasks():  # 获取计划任务
    print('获取计划任务...')
    schtasks_info = os.popen('schtasks.exe').read()
    schtasks = re.findall(r'\n(.+?)文件夹:', schtasks_info, re.S)[0]
    return schtasks


def firewall():  # 获取防火墙信息
    print('获取防火墙信息...')
    firewall_info = os.popen('netsh firewall show state').read()
    firewall = re.findall(r'\n(.+?)重要信息', firewall_info, re.S)[0]
    return firewall


def CVEcheck():  # 检查补丁情况
    print('检查补丁情况...')
    systeminfo = os.popen('systeminfo').read()
    if re.search('Server 2003', systeminfo) != None:
        system = 'win2k3'
    elif re.search('XP', systeminfo) != None:
        system = 'winxp'
    elif re.search('Server 2008 R2', systeminfo) != None:
        system = 'win2k8r2'
    elif re.search('Server 2008', systeminfo) != None:
        system = 'win2k8'
    elif re.search('Server 2012 R2', systeminfo) != None:
        system = 'win2k12r2'
    elif re.search('Server 2012', systeminfo) != None:
        system = 'win2k12'
    elif re.search('Server 2019', systeminfo) != None:
        system = 'win2k19'
    else:
        print('识别错误或是其他OS')
        return '识别错误或是其他OS'
    patch_num = os.popen(
        'systeminfo | findstr "KB4012598 KB4012212 KB4012213 KB4500331 KB4499180 KB4499175 KB4512486 KB4512482 KB4512489 KB4511553"').read()
    # 开始检查MS17-010补丁情况
    MS17010 = 'ok'
    if system == 'win2k3' or system == 'winxp' or system == 'win2k8':
        if re.search('KB4012598', patch_num) == None:
            MS17010 = 'MS17-010'
    if system == 'win2k8r2':
        if re.search('kb4012212', patch_num) == None:
            MS17010 = 'MS17-010'
    if system == 'win2k12r2':
        if re.search('kb4012213', patch_num) == None:
            MS17010 = 'MS17-010'

    # 开始检查CVE-2019-0708补丁情况
    CVE20190708 = 'ok'
    if system == 'win2k3' or system == 'winxp':
        if re.search('kb4500331', patch_num) == None:
            CVE20190708 = 'CVE-2019-0708'
    if system == 'win2k8':
        if re.search('kb4499180', patch_num) == None:
            CVE20190708 = 'CVE-2019-0708'
    if system == 'win2k8r2':
        if re.search('kb4499175', patch_num) == None:
            CVE20190708 = 'CVE-2019-0708'

    # 开始检查CVE-2019-1181补丁情况
    CVE20191181 = 'ok'
    if system == 'win2k8r2':
        if re.search('kb4512486', patch_num) == None:
            CVE20191181 = 'CVE-2019-1181'
    if system == 'win2k12':
        if re.search('kb4512482', patch_num) == None:
            CVE20191181 = 'CVE-2019-1181'
    if system == 'win2k12r2':
        if re.search('kb4512489', patch_num) == None:
            CVE20191181 = 'CVE-2019-1181'
    if system == 'win2k19':
        if re.search('kb4511553', patch_num) == None:
            CVE20191181 = 'CVE-2019-1181'

    ispatch =[]
    if MS17010 == CVE20190708 == CVE20191181 == 'ok':
        ispatch.append('检测补丁均存在！')
    if MS17010 == 'MS17-010':
        ispatch.append('MS17-010、')
    if CVE20190708 == 'CVE-2019-0708':
        ispatch.append('CVE-2019-0708、')
    if CVE20191181 == 'CVE-2019-1181':
        ispatch.append('CVE-2019-1181、')
    return ispatch


def eventANDstartup():  # 打开系统日志页面和启动项页面，然后手动查看
    print('为您打开系统日志页面和启动项页面，请手动查看')
    os.popen('eventvwr')  # 打开日志页面
    os.popen('msconfig')  # 打开启动项页面


cpu = cpu()
mem = mem()
disk = disk()
account = account()
tasklist = tasklist()
service = service()
schtasks = schtasks()
firewall = firewall()
CVEcheck = CVEcheck()

report = '----------------\n【基础信息】：\n{}{}{}\n----------------\n【账号信息】：\n{}\n----------------\n【防火墙信息】：\n{}\n----------------\n【补丁情况】：\n{}\n----------------\n【进程列表】：\n{}\n----------------\n【服务列表】：\n{}\n----------------\n【计划任务】：\n{}'.format(cpu,mem,disk,account,firewall,CVEcheck,tasklist,service,schtasks)
with open("主机巡查报告.txt", "a") as f:
    f.write(report)
print('报告已生成完毕！')
eventANDstartup()
