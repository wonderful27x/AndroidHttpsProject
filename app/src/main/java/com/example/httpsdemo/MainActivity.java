package com.example.httpsdemo;

import androidx.appcompat.app.AppCompatActivity;
import android.app.ProgressDialog;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * 这是一个https的项目，结合openssl生成证书，并校验证书
 * 校验主要有两大部分，
 * 一：域名校验，校验证书的域名（申请签名请求文件时填写的域名Common Name：xxx）是否和当前请求的域名一致
 * 二：证书校验，校验证书是否是权威机构CA颁发的，由于向正规机构申请费用很高，这里我们通过openssl生成了自己
 * 的根证书，自己充当认证机构，assets目录下存放的就是这个根证书，只要是这个根证书签名的证书我们都认为是安全的
 *
 * TODO 双向认证没有实现
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    private Button button;
    private TextView textView;
    private ProgressDialog progressDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        button = findViewById(R.id.button);
        textView = findViewById(R.id.text);
        progressDialog = new ProgressDialog(this);

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                progressDialog.show();
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        //httpRequest();
                        httpsRequest();
                    }
                }).start();
            }
        });
    }

    //普通http请求
    private void httpRequest(){
        String urlString = "http://192.168.0.103:8080/httpsServer/httpsDemo";
        BufferedReader bufferedReader = null;
        try {
            URL url = new URL(urlString);
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setConnectTimeout(5000);
            urlConnection.setRequestMethod("GET");
            urlConnection.connect();
            final int code = urlConnection.getResponseCode();
            final StringBuffer responseContent = new StringBuffer();
            if (code == HttpURLConnection.HTTP_OK){
                InputStream inputStream = urlConnection.getInputStream();
                bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                String line;
                while ((line = bufferedReader.readLine()) != null){
                    responseContent.append(line);
                    responseContent.append("\n");
                }
            }

            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    textView.setText("code: " + code + "\n" + responseContent.toString());
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }finally {
            progressDialog.dismiss();
            if (bufferedReader != null){
                try {
                    bufferedReader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }


    //https安全加密
    //一、证书有效性校验
    //从assets目录中读取我们预先放置的CA根证书，
    //校验服务器证书，如果是CA根证书签发的都信任
    //二、域名校验
    //判断证书的域名是不是自己想要请求的域名
    private void httpsRequest(){
        String urlString = "https://192.168.0.103:8843/httpsServer/httpsDemo";
        BufferedReader bufferedReader = null;
        try {
            URL url = new URL(urlString);
            HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
            urlConnection.setConnectTimeout(5000);
            urlConnection.setRequestMethod("GET");
            //域名校验
            urlConnection.setHostnameVerifier(new VerifyHostName());
            //证书校验
            urlConnection.setSSLSocketFactory(createHandSSLSocketFactory());
            urlConnection.connect();
            final int code = urlConnection.getResponseCode();
            final StringBuffer responseContent = new StringBuffer();
            if (code == HttpURLConnection.HTTP_OK){
                InputStream inputStream = urlConnection.getInputStream();
                bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                String line;
                while ((line = bufferedReader.readLine()) != null){
                    responseContent.append(line);
                    responseContent.append("\n");
                }
            }

            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    textView.setText("code: " + code + "\n" + responseContent.toString());
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }finally {
            progressDialog.dismiss();
            if (bufferedReader != null){
                try {
                    bufferedReader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    //域名校验,校验证书上的域名是否和请求的域名一致
    private class VerifyHostName implements HostnameVerifier {
        @Override
        //hostname：请求的url域名
        //session.getPeerHost()：服务器返回的主机名
        public boolean verify(String hostname, SSLSession session) {
            try {
                //通过session获取服务器证书
                X509Certificate[] x509Certificates = (X509Certificate[]) session.getPeerCertificates();
                for (X509Certificate x509Certificate:x509Certificates){
                    //X500Principal包含了证书的关键信息（申请签名请求文件时填写的信息），如域名，机构等，
                    X500Principal principal = x509Certificate.getSubjectX500Principal();
                    String principalName = principal.getName();
                    //principalName --》1.2.840.113549.1.9.1=#1611313035363330393737364071712e636f6d,CN=192.168.0.105,OU=wonderfulService3,O=wonderfulService3,L=beijing,ST=beijing,C=CN
                    Log.d(TAG, "服务器证书信息 : " + principalName);

                    if (principalName == null || principalName.isEmpty())continue;

                    String[] split = principalName.split(",");
                    if (split.length > 0){
                        for (String content:split){
                            //排除非域名标签
                            if (!content.startsWith("CN="))continue;
                            //判断请求的url的域名是否和证书填写的域名一致
                            //截取域名
                            String registerHost = content.substring(3);
                            if (hostname.equals(registerHost)){
                                showMessage("域名校验成功： ", hostname + " = " + registerHost);
                                Log.d(TAG, "域名校验成功： " + hostname + " = " + registerHost);
                                return true;
                            }else {
                                showMessage("域名校验失败： ", hostname + " ！= " + registerHost);
                                Log.d(TAG, "域名校验失败： " + hostname + " ！= " + registerHost);
                            }
                        }
                    }
                }
            } catch (SSLPeerUnverifiedException e) {
                e.printStackTrace();
            }
            return false;
        }
    }

    //使用CA根证书来创建SSLSocket加密工厂
    //TODO 使用Keystore文件来创建TrustManager，实现自动校验
    private SSLSocketFactory createAutoSSLSocketFactory(){
        try {
            //拿到根证书对象
            InputStream open = getAssets().open("wonderful_ca.crt");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate = certificateFactory.generateCertificate(open);

            //创建密钥库keystore，并将证书添加进去
            //使用默认jks类型
            String keystoreType = KeyStore.getDefaultType();
            KeyStore keyStore = KeyStore.getInstance(keystoreType);
            keyStore.load(null);
            keyStore.setCertificateEntry("wonderfulCa",certificate);

            //使用keystore来创建trustManager
            String defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(defaultAlgorithm);
            trustManagerFactory.init(keyStore);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

            //使用trustManager来创建Context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null,trustManagers,null);
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
            showMessage("证书校验失败： ",e.getMessage());
            Log.d(TAG, "证书校验失败： " + e.getMessage());
        }
        return null;
    }

    //使用CA根证书来创建SSLSocket加密工厂
    //TODO 重写TrustManager，手动对证书进行校验
    private SSLSocketFactory createHandSSLSocketFactory(){
        try {
            //那个根证书对象
            InputStream open = getAssets().open("wonderful_ca.crt");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            final Certificate certificate = certificateFactory.generateCertificate(open);
            //使用trustManager来创建Context

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null,new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                            //客户端认证
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                            //服务端认证
                            for (X509Certificate x509Certificate:chain){
                                //判断是否过期
                                x509Certificate.checkValidity();
                                try {
                                    //证书校验，判断证书是否是Ca签发的
                                    x509Certificate.verify(certificate.getPublicKey());
                                } catch (InvalidKeyException e) {
                                    e.printStackTrace();
                                } catch (NoSuchAlgorithmException e) {
                                    e.printStackTrace();
                                } catch (NoSuchProviderException e) {
                                    e.printStackTrace();
                                } catch (SignatureException e) {
                                    e.printStackTrace();
                                }
                            }
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            }, null);

            return sslContext.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
            showMessage("证书校验失败： ",e.getMessage());
            Log.d(TAG, "证书校验失败： " + e.getMessage());
        }
        return null;
    }

    private void showMessage(final String title, final String message){
        new Handler(getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this,title + message,Toast.LENGTH_SHORT).show();
            }
        });
    }
}
