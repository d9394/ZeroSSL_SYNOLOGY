# ZeroSSL_SYNOLOGY    
---   
ZeroSSL certifidate update for SYNOLOGY DSM7    
1、申请ZeroSSL的HTTPS免费DV证书，用email方式验证域名（因为运营商普遍屏蔽了80和443端口）    
2、检查ZeroSSL证书的时效，到期前30天内再次申请    
3、下载ZeroSSL证书并更新到SYNOLOGY存储（DSM7版本，DSM6未测试）    
4、由于ZeroSSL免费用户限制3次证书（Cancle和Revoke的证书也算一次），因此每3次更新后需删除ZeroSSL账户重启注册，然后再重新申请域名证书，删除和注册这步目前只能手工操作，注册后需得新获取API  
---   
以上功能基本上都验证过，但不排除有异常情况，代码仍需改良中
---   
