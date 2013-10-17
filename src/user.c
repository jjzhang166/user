/*
 ============================================================================
 Name        : user.c
 Author      : lsc
 Version     :
 Copyright   : R & D Center of Internet of Things Security
 Description : Hello World in C, Ansi-style
 ============================================================================
 */


#include "user.h"

#define HOME "./"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

static char *ASU_ip_addr;

typedef struct user
{
    int user_ID;
    int client_socket;
    //client_socket==NOT_LOGIN,表示没有用户登录,
    //client_socket==NOT_IN_USE,表示没有用户注册,
}user;

//多线程共享user_table
static user user_table[USER_AMOUNT_MAX];
//访问user_table时要使用的信号量
pthread_mutex_t user_table_mutex;


int init_server_socket()
{
    struct sockaddr_in server_addr;

    // 接收缓冲区
    int nRecvBuf = 32*1024; //设置为32K
    //发送缓冲区
    int nSendBuf = 32*1024; //设置为32K

    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(CHAT_LISTEN_PORT);

    int server_socket = socket(AF_INET,SOCK_STREAM,0);

    setsockopt(server_socket,SOL_SOCKET,SO_RCVBUF,(const BYTE *)&nRecvBuf,sizeof(int));
    setsockopt(server_socket,SOL_SOCKET,SO_SNDBUF,(const BYTE *)&nSendBuf,sizeof(int));

    if( server_socket < 0)
    {
        perror("socket error!");
        exit(1);
    }

    if( bind(server_socket,(struct sockaddr*)&server_addr,sizeof(server_addr)))
    {
        perror("server bind error Failed!");
        exit(1);
    }

    if ( listen(server_socket, 5) )
    {
        printf("Server Listen Failed!");
        exit(1);
    }
    return server_socket;
}


int connect_to_asu()
{
	int client_socket;
    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;
    socklen_t server_addr_length;

    int nRecvBuf = 32*1024; //设置为32K
    int nSendBuf = 32*1024; //设置为32K

    //设置一个socket地址结构client_addr,代表客户端internet地址, 端口
    bzero(&client_addr,sizeof(client_addr)); //把一段内存区的内容全部设置为0
    client_addr.sin_family = AF_INET;    //internet协议族
    client_addr.sin_addr.s_addr = htons(INADDR_ANY);//INADDR_ANY表示自动获取本机地址
    client_addr.sin_port = htons(0);    //0表示让系统自动分配一个空闲端口
    //创建用于internet的流协议(TCP)socket,用client_socket代表客户端socket

    if( (client_socket = socket(AF_INET,SOCK_STREAM,0)) < 0){
        printf("Create Socket Failed!\n");
        return FALSE;
    }
    //把客户端的socket和客户端的socket地址结构联系起来
    if( bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr))){
        printf("Client Bind Port Failed!\n");
        return FALSE;
    }

    //设置一个socket地址结构server_addr,代表服务器的internet地址, 端口
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if(inet_aton(ASU_ip_addr,&server_addr.sin_addr) == 0) //服务器的IP地址来自程序的参数
    {
        printf("Server IP Address Error!\n");
        return FALSE;
    }
    server_addr.sin_port = htons(CHAT_SERVER_PORT);
    server_addr_length = sizeof(server_addr);

    setsockopt(client_socket,SOL_SOCKET,SO_RCVBUF,(const BYTE *)&nRecvBuf,sizeof(int));
    setsockopt(client_socket,SOL_SOCKET,SO_SNDBUF,(const BYTE *)&nSendBuf,sizeof(int));

    //客户端向服务器发起连接,连接成功后client_socket代表了客户端和服务器的一个socket连接
    if(connect(client_socket,(struct sockaddr*)&server_addr, server_addr_length) < 0)
    {
        printf("AE Can Not Connect To ASU %s!\n",ASU_ip_addr);
        return FALSE;
    }
    return client_socket;

}

int send_to_peer(int new_server_socket, BYTE *send_buffer, int send_len)
{

	int length = send(new_server_socket,send_buffer,send_len,0);
	//printf("--- send %d bytes ---\n",length);
	printf("---------发送 %d 字节数据！---------\n",length);

    if(length <0){
        printf("Socket Send Data Failed Or Closed\n");
        close(new_server_socket);
        return FALSE;
    }
	else
		return TRUE;
}


int recv_from_peer(int new_server_socket, BYTE *recv_buffer, int recv_len)
{
	int length = recv(new_server_socket,recv_buffer, recv_len,MSG_WAITALL);
	if (length < 0)
	{
		printf("Receive Data From Server Failed\n");
		return FALSE;
	}else if(length < recv_len)
	{
		printf("Receive data from server less than required.\n");
		return FALSE;
	}else if(length > recv_len)
	{
		printf("Receive data from server more than required.\n");
		return FALSE;
	}
	else
	{
		//printf("--- receive data succeed, %d bytes. ---\n",length);
		printf("---------接收数据成功, 接收 %d 字节数据！---------\n",length);
		return TRUE;
	}

}


BOOL writeUserCertFile(char *username, BYTE buf[], int len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	sprintf(certname, "./userfile/%s_cert.pem", username);

//	printf("user cert file name: %s\n", certname);

	fp = fopen(certname, "w");
	if (fp == NULL)
	{
		printf("open cert file failed!\n");
		return FALSE;
	}
	int res = fwrite(buf, 1, len, fp);
//	printf("user cert's length is %d\n", len);
	fclose(fp);
//	printf("write user cert complete!\n");
	printf("用户接收CA签发后的证书并保存成功!\n");

	return TRUE;
}


/*************************************************

Function:    // getprivkeyfromkeyfile
Description: // 从密钥文件中提取出私钥的RSA结构体，以便后续进行公钥的提取以及私钥的签名操作
Calls:       // openssl读取私钥PEM文件函数、从PEM文件读取私钥RSA函数
Called By:   //
Input:	     //	userID-用户名，0-CA，非零-用户编号
Output:      //	私钥的RSA指针
Return:      // RSA *
Others:      // 本函数不要与getprivkeyfromprivkeyfile混淆，本函数为了2013.8.15认证服务其签发证书的演示所填加,请不要调用此函数。

*************************************************/

RSA * getprivkeyfromkeyfile(char *username)
{
	//RSA rsa_struct;
	RSA* rsa;

	char keyname[40];
	memset(keyname,0,sizeof(keyname));


	sprintf(keyname, "./private/%s.pem", username);

	BIO * in = BIO_new_file(keyname, "rb");
	if (in == NULL )
		return FALSE;
	rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL ); //提取私钥
	BIO_free(in);
	return rsa;
}

/*************************************************

Function:    // user_gen_cert_request
Description: // 用户生成自签名证书请求文件
Calls:       // X509_REQ相关函数
Called By:   //
Input:	     //	userID---待读取文件编号，0-CA，非零-用户编号
Output:      //	证书请求文件(txt和PEM文件)
Return:      // void
Others:      //

*************************************************/

void user_gen_cert_request(char *username)
{
	X509_REQ *req;
	int ret = 0;
	long version = 3;
	X509_NAME *name;
	char mdout[20]; //bytes不要超过30位
	int mdlen = 0;
	const EVP_MD *md;
	BIO *b;

	RSA *rsa;
	EVP_PKEY * privkey,* pubkey;

	//初始化申请
	req = X509_REQ_new();
	ret = X509_REQ_set_version(req, version);

	//填写申请者相关信息
	char countryname[10] = "CN";
	char provincename[10] = "JS";
	char organizationname[10] = "CIOTC";

	char commonname[50];
	memset(commonname,0,sizeof(commonname));
	memcpy(commonname,username,strlen(username));
	commonname[strlen(username)] = '\0';

	name = X509_REQ_get_subject_name(req);
	X509_NAME_add_entry_by_NID(name, NID_countryName, V_ASN1_PRINTABLESTRING,
			(unsigned char*) countryname, strlen(countryname), -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName,
			V_ASN1_PRINTABLESTRING, (unsigned char*) provincename,
			strlen(provincename), -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_organizationName,
			V_ASN1_PRINTABLESTRING, (unsigned char*) organizationname,
			strlen(organizationname), -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_commonName, V_ASN1_PRINTABLESTRING,
			(unsigned char*) commonname, strlen(commonname), -1, 0);



	/*提取用户的公钥*/
	rsa = RSA_new();


	rsa = getprivkeyfromkeyfile(commonname);

	RSA *tem = RSAPublicKey_dup(rsa);
	if (tem == NULL )
	{
		printf("提取用户公钥失败\n");
	}

	//将用户的RSA公钥转换成EVP_PKEY格式
	pubkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pubkey, tem);
	if (pubkey == NULL )
	{
		printf("RSA->EVP_PKEY 转化公钥失败\n");
	}

	//将用户的EVP_PKEY格式公钥添加到证书申请文件中的公钥字段部分
	ret = X509_REQ_set_pubkey(req, pubkey);
	printf("证书请求文件中的公钥字段添加完成！\n");


	/*提取用户的私钥来对证书认证申请文件进行签名(除签名字段之外的所有字段)*/
//	rsa = RSA_new();
//	rsa = getprivkeyfromkeyfile(user_ID);

	if (rsa == NULL )
	{
		printf("提取用户私钥失败！\n");
		return;
	}
	privkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(privkey, rsa);
	if (privkey == NULL )
	{
		printf("RSA->EVP_PKEY 转化私钥失败\n");
	}

	//hash 算法
	md = EVP_sha1();
	ret = X509_REQ_digest(req, md, (unsigned char *) mdout, &mdlen); //摘要
	ret = X509_REQ_sign(req, privkey, md); //用私钥签名
	if (!ret)
	{
		printf("私钥签名失败\n");
		X509_REQ_free(req);
		return;
	}
	// 写入文件,PEM和TXT格式
	else
	{
		printf("用户用私钥对证书请求文件进行签名成功!\n");
		//将用户证书请求可视化打印输出出来，输出保存到txt文件
		char userreqname[50];
		memset(userreqname,0,sizeof(userreqname));
		sprintf(userreqname,"./userfile/%s_req.txt",commonname);
		b = BIO_new_file(userreqname, "w"); //USER_REQ_PRINT
		X509_REQ_print(b, req);
		BIO_free(b);

		//将用户证书请求保存起来，保存到PEM文件
		memset(userreqname,0,sizeof(userreqname));
		sprintf(userreqname,"./userfile/%s_req.pem",commonname);
		b = BIO_new_file(userreqname, "w");
		PEM_write_bio_X509_REQ(b, req);
		BIO_free(b);

//		//用户用自己的公钥先自己来验证证书请求的签名字段
//		ret = X509_REQ_verify(req, pubkey);
//		if (ret == 0)
//		{
//			printf("证书请求验证失败\n");
//		}
//		//printf("证书请求签名字段验证结果为：%d\n", ret);
//		printf("证书请求验证成功\n");
		X509_REQ_free(req);

		printf("用户证书请求文件已成功生成!\n");
		return;
	}
}




BOOL getCertRequData(char *username, BYTE buf[], int *len)
{
	FILE *fp;
	char certrequname[40];
	memset(certrequname, '\0', sizeof(certrequname));//初始化certname,以免后面写入乱码到文件中

	sprintf(certrequname, "./userfile/%s_req.pem",username);


//	printf("cert sign requ file name: %s\n", certrequname);

	fp = fopen(certrequname, "rb");
	if (fp == NULL)
	{
		printf("reading the cert sign requ file failed!\n");
		return FALSE;
	}
	*len = fread(buf, 1, 5000, fp);
//	printf("cert sign requ's length is %d\n", *len);
	fclose(fp);
	printf("将证书签发请求文件保存到缓存buffer成功!\n");

	return TRUE;
}

int fill_certificate_sign_requ_pcaket(char * username,BYTE *cert_request,int *cert_request_len,certificate_sign_requ *certificate_sign_requ_pcaket)
{
	memset((BYTE *)certificate_sign_requ_pcaket, 0, sizeof(certificate_sign_requ));

	printf("\n---用户生成证书签发请求文件过程begin---\n");

	user_gen_cert_request(username);

	if(!(getCertRequData(username,cert_request, cert_request_len)))
	{
		printf("将证书签发请求文件保存到缓存buffer失败!\n");
	}

	printf("---用户生成证书签发请求文件过程end---\n\n");

	memcpy(certificate_sign_requ_pcaket->certificate_sign_requ_buffer,cert_request,*cert_request_len);
	certificate_sign_requ_pcaket->certificate_sign_requ_buffer_len = *cert_request_len;

	//fill WAI packet head
	certificate_sign_requ_pcaket->wai_packet_head.version = 1;
	certificate_sign_requ_pcaket->wai_packet_head.type = 1;
	certificate_sign_requ_pcaket->wai_packet_head.subtype = REQUEST_CERTIFICATE;
	certificate_sign_requ_pcaket->wai_packet_head.reserved = 0;
	certificate_sign_requ_pcaket->wai_packet_head.length = sizeof(certificate_sign_requ);
	certificate_sign_requ_pcaket->wai_packet_head.packetnumber = 255;
	certificate_sign_requ_pcaket->wai_packet_head.fragmentnumber = 0;
	certificate_sign_requ_pcaket->wai_packet_head.identify = 0;

	memcpy(certificate_sign_requ_pcaket->username,username,strlen(username));

	return TRUE;
}

int Processgencertsignrequ(char * username,BYTE *cert_request,int *cert_request_len,certificate_sign_requ *certificate_sign_requ_pcaket)
{
	if (!fill_certificate_sign_requ_pcaket(username,cert_request,cert_request_len,certificate_sign_requ_pcaket))
	{
		printf("fill cert sign requ packet failed!\n");
	}

	return TRUE;
}




int HandleCertSignResp(char *username, certificate_sign_resp *certificate_sign_resp_packet)
{
	if(!writeUserCertFile(username,certificate_sign_resp_packet->usercer.cer_X509,certificate_sign_resp_packet->usercer.cer_length))
	{
		printf("将用户的证书数据保存到PEM文件失败！\n");
	}

	return TRUE;
}

int main(int argc, char **argv)
{
	int asu_socket,user_ID;
	certificate_sign_requ certificate_sign_requ_pcaket;
	certificate_sign_resp certificate_sign_resp_packet;

	OpenSSL_add_all_algorithms();

    if (argc != 3)
    {
		printf("Usage: %s ASU_ip_addr\n", argv[0]);
		exit(1);
	}


	ASU_ip_addr = argv[1];


	//**************************************演示清单第一部分证书签发等操作 begin***************************************************

	char *username = argv[2];

	BYTE cert_request[5000];
	int cert_request_len=0;

	Processgencertsignrequ(username,cert_request,&cert_request_len,&certificate_sign_requ_pcaket);

    asu_socket = connect_to_asu();
	send_to_peer(asu_socket,(BYTE *)&certificate_sign_requ_pcaket, sizeof(certificate_sign_requ_pcaket));

	recv_from_peer(asu_socket,(BYTE *)&certificate_sign_resp_packet, sizeof(certificate_sign_resp_packet));
	HandleCertSignResp(username, &certificate_sign_resp_packet);

	//**************************************演示清单第一部分离线证书签发等操作 end********************************************************

	return 0;

}


