#双向认证https加密通信，使用openssl生成CA根证书、服务器证书和客户端证书，并配置tomcat，向浏览器添加根证书
> https://blog.csdn.net/gengxiaoming7/article/details/78505107
> https://blog.csdn.net/xuebing1995/article/details/80061856

	https是http security的缩写，即安全的http服务，一般是http + SSL/TLS,从结构上来说SSL/TLS是架设在运输层和应用层中间的一层安全协议，
 一般在C/S架构下会首先使用非对称加密算法来协商出用于数据加密的对称密钥，一般是客户端产生这个对称加密密钥，然后使用服务端的公钥进行加密传给服务器，
 服务端用私钥进行解密。然而如果攻击者伪装成服务器将自己的公钥给客户端进行加密再用自己的私钥进行解密，那么他就能获得双方的数据加密密钥，这仍然是危险的，
 所以客户端需要确认公钥是服务器的而不是攻击者的，这就需要一个权威机构-认证中心CA来将某个公钥与其对应的实体绑定，这就是数字证书，
 证书包含了公钥以及公钥的持有者的信息，同时CA认证中心用自己的私钥对证书进行数字签名防止证书的伪造和篡改。我们应当注意到CA认证是为解决公钥的安全分配而产生的。
	在https通信前，服务器会将自己的数字证书发送给客户端，客户端使用CA认证中心的公钥来认证证书的有效性，然后就能取出数字证书里面的公钥（服务器的公钥）
 进行后续的操作了。客户端如浏览器一般会设置一些根证书，我的理解就是根证书包含了受信任的认证中心的公钥，用于认证数字证书的有效性。所以我们可以看到
 其中包含了两个重要的证书，CA的根证书和CA签发的服务器证书。上面说的是单项认证的情况，及客户端认证服务器，双向认证就是多增加服务器对客户端的认证，其中CA认证
 中心会签发一份客户端证书。
	由于找权威的认证中心签发证书费用昂贵，我们可以使用openssl自己制作证书，然后自己充当CA认证机构给证书签名。这书的格式一般使用X.509协议标准。
	#注意，证书合法性的校验一般暗含了两大部分
	#一：域名校验，申请证书签名请求文件时填写的Common Name是否和客户端正在访问的域名一致
	#二：证书校验，证书是否是CA认证中心颁发的
	
	一、自己充当CA认证机构，制作认证中心的CA根证书
	1.生成CA根证书私钥
	#生成2048位非对称加密私钥wonderful_ca_private.key，
	#-des3表示对生成的私钥使用CBC模式的DES加密算法进行对称加密
	openssl genrsa -des3 -out wonderful_ca_private.key 2048
	2.为了方便将加密的私钥转成非加密的私钥（建议保留密码）
	openssl rsa -in wonderful_ca_private.key -out wonderful_ca_private.key
	3.生成CA根证书签名请求文件
	openssl req -new -key wonderful_ca_private.key -out wonderful_ca.csr
	4.使用CA根证书私钥签署CA根证书签名请求文件生成自签名证书，将这个自签名证书作为认证中心的CA根证书
	#生成x509协议证书，有效期3650天-10年
	openssl x509 -req -in wonderful_ca.csr -out wonderful_ca.crt -signkey wonderful_ca_private.key -days 3650
	5.将证书导出成浏览器支持的.p12格式
	openssl pkcs12 -export -in wonderful_ca.crt -inkey wonderful_ca_private.key -out wonderful_ca.p12
	#注意，其中3、4步骤可以合并成一步
	openssl req -new -x509 -key wonderful_ca_private.key -out wonderful_ca.crt -days 3650
	
	二、生成服务器端数字证书
	1.生成服务器端私钥
	openssl genrsa -des3 -out service_private.key 2048
	2.转成非加密私钥（建议保留密码）
	openssl rsa -in service_private.key -out service_private.key
	3.生成证书签名请求文件
	#特别注意，在填写Common Name时必须填写自己的域名或ip地址，在本机tomcat测试时发现，
	#访问浏览器时填写本机ip和localhost的效果是不一样的，只有填写的和注册时的Common Name一致时才没有警告
	#其实也可以这么理解，证书的作用就是告诉客户端服务器的身份和对应公钥，所以标志服务器身份的ip或域名肯定要和访问时一致，这就是域名校验
	openssl req -new -key service_private.key -out service_request.csr
	4.将服务器证书签名请求文件给CA认证中心进行签名生成最终的服务器数字证书
	#使用认证中心CA的根证书对请求文件进行签名生成服务器证书，有效期3650天-10年
	openssl x509 -req -in service_request.csr -CA wonderful_ca.crt -CAkey wonderful_ca_private.key -CAcreateserial -out service.crt -days 3650
	5.将证书导出成浏览器支持的.p12格式
	openssl pkcs12 -export -in service.crt -inkey service_private.key -out service.p12
	6.校验证书
	openssl verify -CAfile wonderful_ca.crt service.crt
	
	三、生成客户端数字证书
	1.生成客户端私钥
	openssl genrsa -des3 -out client_private.key 2048
	2.转成非加密私钥（建议保留密码）
	openssl rsa -in client_private.key -out client_private.key
	3.生成证书签名请求文件
	openssl req -new -key client_private.key -out client_request.csr
	4.将服务器证书签名请求文件给CA认证中心进行签名生成最终的服务器数字证书
	#使用认证中心CA的根证书对请求文件进行签名生成服务器证书，有效期3650天-10年
	openssl x509 -req -in client_request.csr -CA wonderful_ca.crt -CAkey wonderful_ca_private.key -CAcreateserial -out client.crt -days 3650
	5.将证书导出成浏览器支持的.p12格式
	openssl pkcs12 -export -in client.crt -inkey client_private.key -out client.p12
	6.校验证书
	openssl verify -CAfile wonderful_ca.crt client.crt
	
	四、配置服务端tomcat
	1.将CA根证书.p12格式转成.jks格式文件
	#使用JDK自带的keytool转换
	keytool -importkeystore -srckeystore wonderful_ca.p12 -srcstoretype PKCS12 -destkeystore wonderful_ca.jks -deststoretype JKS
	2.将服务器证书.p12格式转成.jks格式文件
	keytool -importkeystore -srckeystore service.p12 -srcstoretype PKCS12 -destkeystore service.jks -deststoretype JKS
	3.将客户端证书.p12格式转成.jks格式文件
	keytool -importkeystore -srckeystore client.p12 -srcstoretype PKCS12 -destkeystore client.jks -deststoretype JKS
	
	#单项认证
	-> 将上述生成的所有文件放置到tomcat的conf/https目录下
	-> 编辑conf/server.xml,增加如下内容
	<!--单项认证-->
	<!--keystoreFile 服务器证书-->
	<!--keystorePass 证书密码-->
	<!--keystoreType 证书类型-->  
	<Connector port="8843" protocol="org.apache.coyote.http11.Http11NioProtocol"
	   maxThreads="150" 
	   SSLEnabled="true" 
	   scheme="https" 
	   secure="true"
	   sslProtocol="TLS" 
	   clientAuth="false"
	   keystoreFile="conf/https/service.p12" 
	   keystorePass="service@p12"            
	   keystoreType="PKCS12"                           
	   /> 
	   
	#双向项认证
	-> 将上述生成的所有文件放置到tomcat的conf/https目录下
	-> 编辑conf/server.xml,增加如下内容
	<!--双项认证-->
	<!--keystoreFile 服务器证书，传给客户端，客户端会使用根证书校验其合法性-->
	<!--keystorePass 证书密码-->
	<!--keystoreType 证书类型-->
	<!--truststoreFile 添加根证书为信任证书，用于校验客户端证书的合法性-->
	<!--truststorePass 证书密码-->
	<!--truststoreType 证书类型--> 
	<Connector port="8843" protocol="org.apache.coyote.http11.Http11NioProtocol"
	   maxThreads="150" 
	   SSLEnabled="true" 
	   scheme="https" 
	   secure="true"
	   sslProtocol="TLS" 
	   clientAuth="true"
	   keystoreFile="conf/https/service.p12"        
	   keystorePass="service@p12"                   
	   keystoreType="PKCS12"                        
	   truststoreFile="conf/https/wonderful_ca.jks" 
	   truststorePass="wonderful@jks"               
	   truststoreType="JKS" 	                    
	   /> 
	   
	五、配置客户端浏览器
	#单项认证
	-> 找到浏览器设置证书的地方，在受信任的根证书颁发机构导入ca根证书wonderful_ca.crt
	#当浏览器访问服务器时，服务器首先把自己的证书service.p12发给浏览器，浏览器使用根证书wonderful_ca.crt
	#去校验服务器证书的合法性，由于服务器证书service.p12是认证中心wonderful_ca.crt签发的，所以认证通过
	
	#双向认证
	-> 找到浏览器设置证书的地方，在受信任的根证书颁发机构导入ca根证书wonderful_ca.crt
	-> 找到浏览器设置证书的地方，在个人或您的证书中导入客户端证书client.p12
	#当浏览器访问服务器时，服务器首先把自己的证书service.p12发给浏览器，浏览器使用根证书wonderful_ca.crt
	#去校验服务器证书的合法性，由于服务器证书service.p12是认证中心wonderful_ca.crt签发的，所以认证通过
	#浏览器也将自己的证书client.12发给服务器，服务器使用根证书wonderful_ca.jks去校验客户端证书的合法性，
	#由于客户端证书client.p12是认证中心wonderful_ca.crt签发的，所以认证通过
	
	#注意，单项认证测试时发现，在不用的浏览器上有些差异，按照上面的步骤进行配置，火狐和IE浏览器没有警告信息，而谷歌浏览器仍然有警告
	#双向认证都失败了
	
	
	