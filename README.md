# 使用方法 #

以常见的生成服务器的HTTPS证书为例<br/>
1. 首先需要创建一个CA证书，修改 CA_CONFIG.ini 文件，配置CA证书的属性<br/>
2. 执行 mkca.py 将会生成2个文件，分别是CA根证书和CA证书的私钥<br/>
3. 修改 config.ini 文件，配置服务器证书的属性<br/>
4. 执行 make_cert.py 将会生成2个文件，分别是服务器的证书和私钥<br/>
