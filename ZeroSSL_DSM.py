#!/usr/bin/python3.8
#coding=utf8

import requests
import imaplib
import email
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
import os
import zipfile
import io
import json
import ast
from time import sleep
import subprocess

DOMAINS = {'xxxx.com': {
	'api_key' : '12345678',    #ZeroSSL的api_key
	'challenge_email' : 'web@xxxx.com',    #ZeroSSL验证域名的邮箱
	'email_user' : 'web',    #邮箱用户
	'email_password' : '123',    #邮箱密码
	'email_server' : 'mail.xxxx.com',    #邮箱服务器地址
	'dsm_ip' : '127.0.0.1',    #DSM的IP
	'dsm_user' : 'admin',    #DSM管理权限用户
	'dsm_pwd' : '123',    #DSM管理密码
	'certificate_cn' : 'xxxx.com'}    #证书域名
}

#在线生成CSR：https://csrgenerator.com/
csr='''
-----BEGIN CERTIFICATE REQUEST-----
放入你的CSR
-----END CERTIFICATE REQUEST-----
'''
private='''
-----BEGIN PRIVATE KEY-----
放入你的私钥
-----END PRIVATE KEY-----
'''

def zerossl_get_cert(api_key, domain=None, cert_id=None):
	if cert_id:
		url = f'https://api.zerossl.com/certificates/{cert_id}?access_key={api_key}'
	else:
		url = f'https://api.zerossl.com/certificates?access_key={api_key}'
		
	response = requests.get(url)
	if response.status_code != 200:
		raise Exception(f"Failed to retrieve certificates: {response.text}")
	
	certificates = response.json()
	if cert_id:
		return certificates
	
	if domain:
		filtered_certificates = [
			cert for cert in certificates['results'] 
			if cert.get('common_name') == domain
		]
		return filtered_certificates
	else:
		return certificates['results']

def cancel_certificate(api_key, cert_id):
	# 官方API已经不再支持cancel证书功能！
	# Please note that only certificates with status draft or pending_validation can be cancelled
	cancel_url = f'https://api.zerossl.com/certificates/{cert_id}/cancel?access_key={api_key}'
	response = requests.get(cancel_url)
	if response.status_code != 200:
		raise Exception(f"Failed to cancel certificates: {response.text}")

	data = response.json()
	if not data.get('success'):
		raise Exception(f"Failed to cancel certificate: {data['error']}")
	print('Cancel certificate done %s' % cert_id)
	return data

def zerossl_revoke_cert(api_key, cert_id):
    # ZeroSSL 的 Revoke 接口通常是通过 POST 发送到该 URL
    revoke_url = f'https://api.zerossl.com/certificates/{cert_id}/revoke?access_key={api_key}'
    
    try:
        # 尝试执行请求
        # 注意：ZeroSSL 的部分端点不需要 payload，因为参数已经在 URL 里的 access_key 了
        response = requests.post(revoke_url, timeout=15)
        
        # 如果返回 500 或其他错误，不抛出异常，而是记录并返回 False
        if response.status_code != 200:
            print(f"[Error] 吊销失败，HTTP 状态码: {response.status_code}, 详情: {response.text}")
            return False
        
        data = response.json()
        
        # 检查 API 逻辑上的成功标志
        if not data.get('success'):
            error_info = data.get('error', '未知错误')
            print(f"[Error] API 业务逻辑失败: {error_info}")
            return False
            
        print(f'成功吊销证书: {cert_id}')
        return data

    except Exception as e:
        # 捕获所有可能的网络错误、JSON解析错误等
        print(f"[Exception] 运行期间发生异常: {e}")
        return False

def zerossl_verify_domain(api_key, cert_id, challenge_email):
	#参看https://github.com/ajnik/ZeroSSL-CertRenew/blob/master/ZeroSSL_CertRenew.py#L90，要用Verify Domains这个方法
	renew_url = f'https://api.zerossl.com/certificates/{cert_id}/challenges?access_key={api_key}'
	data = {
		'validation_method': 'EMAIL',
		'validation_email' : challenge_email
	}
	response = requests.post(renew_url, data=data)
	"""
	renew_url = f'https://api.zerossl.com/certificates/{cert_id}/challenges/email?access_key={api_key}'
	response = requests.get(renew_url)
	"""
	if response.status_code != 200:
		raise Exception(f"Failed to challenge certificates: {response.text}")

	data = response.json()
	if data.get('success'):
		raise Exception(f"Failed to renew certificate: {data}")
	return data

def zerossl_create_cert(domain, vcsr,validity_days=90, email='youremail@example.com'):
	api_key = DOMAINS[domain]['api_key']
	API_URL = f'https://api.zerossl.com/certificates?access_key={api_key}'
	headers = {
		'Content-Type': 'application/json',
	}
	# 创建证书的请求数据
	payload = {
		'certificate_domains': domain,
		'certificate_validity_days': validity_days,
		'certificate_csr': csr,  # 可选：你可以自己生成 CSR 或留空让 ZeroSSL 生成
		'certificate_type': 'free',  # 'free', 'basic','premium'，根据需要选择
		'email': email,  # 将用于 DCV 验证的电子邮件
	}
	# 发送请求以创建证书
	response = requests.post(API_URL, headers=headers, data=json.dumps(payload))
	# 检查响应
	if response.status_code == 200:  # 请求响应正常
		cert_data = response.json()
		if not cert_data.get('id'):
			print(f'创建证书API请求成功，返回失败: {cert_data}')
			return None
		else :
			print(f"创建新证书成功，返回信息: {cert_data}")
		return cert_data
	else:
		print(f"创建证书API请求失败: {response.status_code} {response.text}")
		return None

def email_verify(email_user, email_password, email_server, email_folder='INBOX'):
	mail = imaplib.IMAP4_SSL(email_server)
	mail.login(email_user, email_password)
	mail.select(email_folder)

	lastday = (datetime.now() - timedelta(days=2)).strftime('%d-%b-%Y')
	retry_times = 20		# 重试检索10次邮件
	while retry_times > 0:
		status, messages = mail.search(None, 'FROM', '"ZeroSSL"', 'SINCE', lastday)
		mail_ids = messages[0].split()
		print(u'搜索邮件：%s, 结果ID：%s' % (status, mail_ids))
		if len(mail_ids)>0 :
			break
		else :
			# 30秒后重新搜索
			sleep(30)
			print(f"重次第{retry_times}次")
			retry_times -= 1
	if retry_times == 0 or len(mail_ids) == 0 :
		# 没有找到邮件?
		return None, None

	max_mail_id = max(list(map(int, messages[0].decode('utf-8').split())))		#只处理时间最近的一封邮件
	status, data = mail.fetch(str(max_mail_id), '(RFC822)')
	msg = email.message_from_bytes(data[0][1])
	# 获取邮件的接收时间
	print(u"ID: %s, 邮件Received Date: %s, 邮件主题：%s" % (max_mail_id,msg["Date"], msg['Subject']))
	if 'ZeroSSL' in msg['from']:
		for part in msg.walk():
			if part.get_content_type() == 'text/plain':
				body = part.get_payload(decode=True).decode('utf-8')
				return email_verify_link(body)

def email_verify_link(email_body):
	link_match = re.search(r'https://secure\.trust-provider\.com/products/EnterDCVCode\?orderNumber=\d+', email_body, re.S)
	code_match = re.search(r'please enter the following key:\s+([A-Za-z0-9\*\-]+)\s+', email_body)
	verification_link = link_match.group(0) if link_match else None
	verification_code = code_match.group(1) if code_match else None
	return verification_link, verification_code

def email_verify_code(verification_link, verification_code):
	# 解析 verification_link
	parsed_url = urlparse(verification_link)
	query_params = parse_qs(parsed_url.query)
	
	# 从查询参数中提取 orderNumber
	order_number = query_params.get('orderNumber', [''])[0]
	# 更新 URL 为 verification_link 中的服务器地址
	url = f"{parsed_url.scheme}://{parsed_url.netloc}/products/EnterDCVCode2"
	
	data = {
		'dcvCode': verification_code,
		'orderNumber': order_number,
		'postPaymentPage': 'N'
	}
	headers = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0"
	}
	response = requests.post(url, data=data, headers=headers)
	if response.status_code != 200:
		print(u'验证码请求失败：%s，请求数据：%s，返回：%s' % ( response.status_code, data, response))
	else:
		#if response.content.decode('utf-8').find('You have entered the correct Domain Control Validation code') :
		if response.content.decode('utf-8').find('Your certificate will now be issued')>0 :
			print(u'验证码验证成功')
			return True		#返回成功标志
		else :
			print(u'验证码验证失败：%s' % (response.content))
	return False

def zerossl_download_cert(api_key,cert_id):
	#https://zerossl.com/documentation/api/download-certificate-inline
	download_url = f'https://api.zerossl.com/certificates/{cert_id}/download/return?access_key={api_key}'
	response = requests.get(download_url)
	if response.status_code == 200 :
		return response.content.decode('utf-8')
	else :
		return None

'''
#output_dir = "/path/to/output/directory"
def download_and_extract_zerossl_certificate(api_key,cert_id, output_dir):
	"""
	下载ZeroSSL证书压缩文件并解压到指定目录。
	#https://zerossl.com/documentation/api/download-certificate/
	参数:
	- api_key: ZeroSSL API密钥
	- cert_id: 证书ID
	- output_dir: 解压证书的目标目录
	"""

	# 创建目标目录（如果不存在）
	if not os.path.exist(output_dir):
		os.makedirs(output_dir, exist_ok=True)

	# ZeroSSL API下载证书的URL
	url = f"https://api.zerossl.com/certificates/{cert_id}/download/zip?access_key={api_key}&include_cross_signed=1"

	# 发送请求并下载证书压缩文件
	response = requests.get(url)
	
	if response.status_code == 200:
		# 使用io.BytesIO在内存中处理下载的内容
		with io.BytesIO(response.content) as zip_file:
			with zipfile.ZipFile(zip_file, "r") as zip_ref:
				zip_ref.extractall(output_dir)
				print('解压文件：%s' % zip_ref.namelist())
		
		print(f"证书已成功下载并解压到 {output_dir}")
	else:
		print(f"下载证书失败，状态码：{response.status_code}")
		print(response.json())
'''

# 处理证书上传更新到synology，默认使用方法2
def update_synology(domain, certificate_data, ver=2):
	if ver==1 :			
		#方法1:webapi，参考https://github.com/TheNytangel/Synology-LetsEncrypt-Remote-Update/blob/master/synology.py
		#private = open('private.key',rb).read()
		# 进行续期操作
		sid = dsm_login(DOMAINS[domain]['dsm_ip'], DOMAINS[domain]['dsm_user'], DOMAINS[domain]['dsm_pwd'])
		certificate_id, desc, default = dsm_get_cert_info(DOMAINS[domain]['dsm_ip'], sid, DOMAINS[domain]['certificate_cn'])
		dsm_upload_cert(DOMAINS[domain]['dsm_ip'], sid, f'{certificate_data["certificate.crt"]}\n{certificate_data["ca_bundle.crt"]}', private, certificate_id, desc, default)
		#print(f"Certificate {cert['id']} for {cert.get('common_name')} has been renewed.")
	elif ver==2:
		#方法2：直接更新文件，参考https://www.debugwar.com/article/setup-an-auto-update-letsencrypt-certificate-on-synology-dsm
		#登陆DSM，获取当前域名证书ID
		sid = dsm_login(DOMAINS[domain]['dsm_ip'], DOMAINS[domain]['dsm_user'], DOMAINS[domain]['dsm_pwd'])
		certificate_id, _, _ = dsm_get_cert_info(DOMAINS[domain]['dsm_ip'], sid, DOMAINS[domain]['certificate_cn'])
		if certificate_id :
			date_now = datetime.now().strftime('%Y%m%d')
			fullchain =  f'{certificate_data["certificate.crt"]}\n{certificate_data["ca_bundle.crt"]}'
			try :
				# 1、先生成落地文件带日期后缀到'/volume1/homes/admin/certificate.backup'
				with open(os.path.join('/volume1/homes/admin/certificate.backup', 'cert.pem.' + date_now),'w') as file:
					file.write(certificate_data["certificate.crt"].replace("\\n", "\n").replace("\\/", "/"))
				with open(os.path.join('/volume1/homes/admin/certificate.backup', 'chain.pem.'+ date_now),'w') as file:
					file.write(certificate_data["ca_bundle.crt"].replace("\\n", "\n").replace("\\/", "/"))
				with open(os.path.join('/volume1/homes/admin/certificate.backup', 'fullchain.pem.'+ date_now),'w') as file:
					file.write(fullchain.replace("\\n", "\n").replace("\\/", "/"))
				with open(os.path.join('/volume1/homes/admin/certificate.backup', 'privkey.pem.'+ date_now),'w') as file:
					file.write(private)
				print('生成本地证书文件完成：%s, 证书ID: %s' % ('/volume1/homes/admin/certificate.backup', certificate_id))
			except Exception as e:
				print('生成本地证书文件失败，原因：%s' %(e))
			else :
				# DSM的NGINX服务
				SYNOLOGY_CERTIFICATE_PATH="/usr/syno/etc/certificate"
				target_path = os.path.join(SYNOLOGY_CERTIFICATE_PATH,'_archive', certificate_id)
				try :
					# 2、将带日期后缀的文件复制去证书目录
					subprocess.run(['sudo', 'cp', '-f', os.path.join('/volume1/homes/admin/certificate.backup', 'cert.pem.'+ date_now), os.path.join(target_path, 'cert.pem')], check=True)
					subprocess.run(['sudo', 'cp', '-f', os.path.join('/volume1/homes/admin/certificate.backup', 'chain.pem.'+ date_now), os.path.join(target_path, 'chain.pem')], check=True)
					subprocess.run(['sudo', 'cp', '-f', os.path.join('/volume1/homes/admin/certificate.backup', 'fullchain.pem.'+ date_now), os.path.join(target_path, 'fullchain.pem')], check=True)
					subprocess.run(['sudo', 'cp', '-f', os.path.join('/volume1/homes/admin/certificate.backup', 'privkey.pem.'+ date_now), os.path.join(target_path, 'privkey.pem')], check=True)
					print('移动本地证书文件完成')
				except Exception as e:
					print('移动本地证书文件失败，原因：%s' %(e))
				else :
					# 3、执行 sudo systemctl restart nginx 命令重启nginx生效新证书
					try:
						subprocess.run(['sudo', 'synosystemctl', 'restart', 'nginx'], check=True)
					except subprocess.CalledProcessError as e:
						print(f"重启nginx失败，错误代码： {e.returncode}")
						return False
					else :
						print(f"重启nginx完成")
				# DSM的邮件服务：dovecot和postfix
				target_path = "/usr/local/etc/certificate/MailServer/"  #dovecot、postfix要分别处理
				
		else :
			print('找不到本地证书信息：%s' % (DOMAINS[domain]['certificate_cn']))
			raise Exception('Domain %s ID not found' % (DOMAINS[domain]['certificate_cn']))
		return False

# 登录DSM函数
# 参考文档：https://global.download.synology.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Login_Web_API_Guide_enu.pdf
# 参考文档：https://github.com/lippertmarkus/synology-le-dns-auto-renew/blob/master/renew.py
def dsm_login(dsm_ip, username, password):
	login_url = f'https://{dsm_ip}:5001/webapi/auth.cgi?api=SYNO.API.Auth&version=7&method=login&account={username}&passwd={password}&session=FileStation&format=sid'
	response = requests.get(login_url, verify=False)
	data = response.json()
	if data['success']:
		print('成功登陆DSM，SID：%s' % (data['data']['sid']))
		return data['data']['sid']
	else:
		raise Exception('Failed to login to Synology DSM. reason: %s' % data)

#获取DSM现有证书
def dsm_get_cert_info(dsm_ip, sid, certificate_cn):
	certificate_id = None
	desc = None
	default = False
	list_url = f'https://{dsm_ip}:5001/webapi/auth.cgi?api=SYNO.Core.Certificate.CRT&version=1&method=list&_sid={sid}'
	response = requests.get(list_url, verify=False)
	data = response.json()
	if data['success']:
		if certificate_cn :
			for certificate in data['data']['certificates'] :
				if certificate["subject"]["common_name"] == certificate_cn:
					certificate_id = str(certificate["id"])
					desc = certificate["desc"]
					default = certificate["is_default"]
					break
				else:
					raise Exception("Certificate %s not found on Synology，result: \n%s" % (certificate_cn, data))
					
		else :
			print("All certificate Data %s " % data)
	else:
		raise Exception("Could not get certificates %s " % data)
	return certificate_id, desc, default

# 上传DSM证书函数
def dsm_upload_cert(dsm_ip, sid, fullchain, private, certificate_id=None, desc="My Certificate", default=False):
	upload_url = f'https://{dsm_ip}:5001/webapi/entry.cgi'
	files = {
		'cert': ("fullchain.pem", fullchain.encode('utf-8')),
		'key': ("privkey.pem", private.encode('utf-8')),
		#'intermediate': ca_bundle,
		'inter_cert' : None
	}
	payload = {
		'api': 'SYNO.Core.Certificate',
		'method': 'import',
		'version': '1',
		'_sid': sid,
		'desc': desc
	}
	if certificate_id :
		#替换证书
		payload['id']= certificate_id
	else :
		#新增证书
		payload['name']=desc
	if default:
		payload["as_default"] = ""		#false
	response = requests.post(upload_url, files=files, data=payload, verify=False)
	data = response.json()
	print(u'DSM返回：%s' % data)
	if not data.get('success'):
		print("证书文件：%s" % files)
		print("提交数据：%s" % payload)
		raise Exception(f"Failed to upload certificate files: {data['error']}")
	return data

# 导入DSM证书函数
def dsm_import_cert(dsm_ip, sid, certificate_id):
	import_url = f'https://{dsm_ip}:5001/webapi/entry.cgi'
	payload = {
		'api': 'SYNO.Core.Certificate',
		'method': 'set',
		'version': '1',
		'_sid': sid,
		'id': certificate_id,
		'desc': 'Imported by Python script'
	}
	response = requests.post(import_url, data=payload, verify=False)
	data = response.json()
	if not data['success']:
		raise Exception(f"Failed to import certificate: {data['error']}")
	return data

# 登出DSM
def dsm_logout(dsm_ip, sid):
	logout_url = f'https://{dsm_ip}:5001/webapi/auth.cgi?api=SYNO.API.Auth&version=7&method=logout&sid={sid}'
	response = requests.get(logout_url, verify=False)
	data = response.json()
	if data['success']:
		return True
	else:
		raise Exception('Failed to logout to Synology DSM. reason: %s' % data)

# 下载ZEROSSL证书
def download_update_files(api_key, cert_id, domain):
	print(f'下载证书 {cert_id}')
	certificate_info = zerossl_download_cert(api_key, cert_id)
	if certificate_info :
		certificate_data = ast.literal_eval(certificate_info)
		print("新证书：%s" % certificate_data)
		#更新本地synology证书
		if update_synology(domain, certificate_data):
			return True
	else :
		print(f'下载{cert_id}证书失败')
	return False

# 检查邮件，并获取链接地址、激活码、隐藏参数
def zerossl_active_cert(domain, api_key, cert_id):
	verification_link, verification_code = email_verify(DOMAINS[domain]['email_user'], DOMAINS[domain]['email_password'], DOMAINS[domain]['email_server'])
	print('Verification Link: %s\nVerification Code: %s' % (verification_link, verification_code))
	if verification_link and verification_code and email_verify_code(verification_link, verification_code) :
		sleep(60)
		#再检查一次证书状态
		new_certificates = zerossl_get_cert(api_key, cert_id = cert_id)
		print('新证书信息：%s' % new_certificates)
		if new_certificates.get('status') == "issued" :
			#下载并更新本地证书
			if download_update_files(api_key, cert_id, domain) :
				return True
		else :
			print('新证书状态问题：%s' % (new_certificates.get('status')))
	else :
		print(f'证书 {cert_id} Email 验证失败，地址：{verification_link}，验证码：{verification_code}')
	return False

# main主程序
def main():
	print('\n--------- ZeroSSL更新程序开始：%s' % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
	for domain in DOMAINS :
		#print('处理域名：%s' % domain)
		certificates = zerossl_get_cert(DOMAINS[domain]['api_key'], domain)
		if len(certificates) == 0 :
			# 新帐号，没有任何证书的情况
			new_certificate = zerossl_create_cert(DOMAINS[domain]['certificate_cn'], csr, validity_days=90, email=DOMAINS[domain]['challenge_email'])
			if new_certificate is not None and new_certificate.get('id'):
				# 创建新证书后重新更新证书信息
				certificates = zerossl_get_cert(DOMAINS[domain]['api_key'], domain)
		for cert in certificates:
			print('证书 ID: %s, Common Name: %s, Status: %s, Expired: %s' % ( cert['id'], cert.get('common_name'),  cert.get('status'), cert.get('expires')))
			if cert.get('status') == "issued" :
				expiration_date_str = cert.get('expires')
				expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d %H:%M:%S')
				remaining_days = (expiration_date - datetime.utcnow()).days
				print(f"证书 {cert['id']} 域名 {cert.get('common_name')} 过期还有 {remaining_days} 日.")
				if remaining_days < 30 :		#证书有效期少于30天
					print(f"更新证书 {cert['id']} 域名 {cert.get('common_name')}...")
					"""
					renew_response = renew_certificate(api_key, cert['id'])
					print(renew_response)
					"""
					# 更新证书要先将当前证书吊销(revoke)
					print('回收 %s 证书：%s' %( cert.get('id'), zerossl_revoke_cert(DOMAINS[domain]['api_key'], cert.get('id'))))
					# 免费证书延期其实是创建一个同域名的新证书
					new_certificate = zerossl_create_cert(cert.get('common_name'), csr, validity_days=90, email=cert.get('validation_emails'))
					if new_certificate is not None and new_certificate.get('id'):
						# 证书验证
						zerossl_verify_domain(DOMAINS[domain]['api_key'], new_certificate.get('id'), DOMAINS[domain]['challenge_email'])
						zerossl_active_cert(domain, DOMAINS[domain]['api_key'], new_certificate.get('id'))
					else :
						print('创建续期证书 %s 失败：%s' % (cert.get('common_name'), new_certificate))

				if remaining_days == 90 :
					print( '新生成的证书 %s 域名 %s 过期日 %s' % (cert['id'],cert.get('common_name'),cert.get('expires')))
					download_update_files(DOMAINS[domain]['api_key'],cert['id'],domain)
				
			elif cert.get('status') == 'expired':	# 状态是过期的证书处理
				print('吊销 %s 过期证书：%s' %( cert.get('id'), zerossl_revoke_cert(DOMAINS[domain]['api_key'], cert.get('id'))))

			elif cert.get('status') == 'draft' :		# 状态是等待验证的证书处理
				zerossl_verify_domain(DOMAINS[domain]['api_key'], cert.get('id'), DOMAINS[domain]['challenge_email'])
				zerossl_active_cert(domain, DOMAINS[domain]['api_key'],cert.get('id'))
			elif cert.get('status') == 'pending_validation' :		# 状态是正在验证的证书处理
				zerossl_active_cert(domain, DOMAINS[domain]['api_key'],cert.get('id'))

			else :
				print("证书 %s 状态为：%s" % (cert['id'], cert.get('status')))
	print('--------- 本次ZeroSSL执行完成. %s\n' % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
					
if __name__ == '__main__' : 
	main()

