# 개요
암호화 기반 공격은 탐지를 우회하며, 정보 유출 및 C2 연결에 사용된다.<br/>

암호화 기반 공격 대응
 - 주로 Unknown 대응(IP, Hostname)과 블랙리스트(JA3) 방식이 많이 사용<br/>
 - 평판 조회는 위협을 빠르게 식별하지만, CSP 호스팅과 같은 경우 평펀 대응의 어려움 존재<br/>
 - JA3는 여전히 블랙리스트 방식에서 유용하게 사용<br/>
   - JA3를 동일하게 구성하는 스푸핑 행위에서는 대응 불가<br/>

<br/>

도메인 스푸핑 또는 IP 평판조회의 한계를 보완할 추가 대응 방법이 필요

# ESD (Encrypted Spoofing Detection)
ESD는 Unknown 기반 탐지 시스템으로 트래픽에서 분석한 내용을 기반으로 값을 제공합니다.<br/>
제공된 값에서 희귀 정도(ex. ff_hash가 5% 미만)를 설정하여 이상행위를 탐지할 수 있습니다.<br/><br/>
ESD는 탐지를 회파히기 위한 암호화 기반 스푸핑 탐지가 주요 기능입니다.<br/>
Telegram 메신저의 프록시, V2RAY 터널링, 상용 VPN 등을 탐지하는데 사용할 수 있습니다.<br/><br/>
스푸핑 탐지에는 주요 모듈(E3C)에 의한 탐지와 암호화 트래픽에서의 일반적이지 않은 행위 정보가 추가됩니다.<br/>

ESD는 트래픽 분석을 위해 Suricata IDS와 연동됩니다. Suricata IDS를 패킷 수집 센서로 사용하며, 수집한 TCP 세션을 ESD에서 재조합하고 위협을 분석합니다.<br/>

학습은 모든 패킷에서 진행되지만, 특정 도메인의 스푸핑을 확인하기 위해서는 위협 알림 장치에서 도메인을 지정해야 할 필요가 있습니다.

## E3C
E3C Fingerprint는 ESD에서 스푸핑 탐지를 위한 주요 모듈입니다. E3C(Encrypted Three Component)는 암호화된 트래픽에서 3가지 주요 행위를 분석하며 이상행위에 대한 지표로 사용합니다.<br/><br/>
3가지 요소(lf, ff, certification)는 암호화 트래픽에서 분석한 고유의 값을 저장하고 통계합니다. 악성 도구가 일반적인 브라우저의 JA3 값으로 스푸핑 하는 상황에서 기존에 집계된 E3C 데이터를 기반으로 Unknown 통신 연결을 확인할 수 있습니다.


<p align="center">
<img src="https://github.com/user-attachments/assets/acf2d5e6-f8ec-42c6-8604-0fa16a1b6299" width="750" height="300"/>
</p>

``` json
{
  "file": "/var/log/rsyslog/127.0.0.1_messages_2024-07-02-1.log",
  "time": "2024-07-02T00:52:33.884789+0900",
  "line_number": 1718,
  "connection": {
    "flow_id": 455865179086798,
    "proto": "tcp",
    "src_ip": "10.0.200.165",
    "src_port": 45878,
    "dest_ip": "172.217.25.162",
    "dest_port": 443,
    "gap": 0
  },
  "tls": {
    "ver": 13,
    "mode": "none",
    "sha": 256,
    "alpn": "h2",
    "sni": "pagead2.googlesyndication.com"
  },
  "fingerprint": {
    "csv_string": "769,771_47,53,156,157,4865,4866,4867,49171,49172,49195,49196,49199,49200,52392,52393_5,10:[23,24,29],11:[0],13:[1025,1027,1281,1283,1537,2052,2053,2054],16:[h2,http/1.1],18,23,27:[2],35,43:[771,772],45,51,2570,17513,35466,65037,65281",
    "csv_hash": "e9fb2b61d66e20b783bb7ec8",
    "csv_last": "2024-07-02",
    "lf_hash": "80a40546a84a401d3fbe6f33",
    "lf_last": "2024-07-02",
    "lf_total_count": 687,
    "lf_ratio": 100.0,
    "ff_hash": "eecd262c3ecab667b61ebb70",
    "ff_ratio": 14.8,
    "certification": "6b2fd0dabc922b3503a2b899",
    "certification_last": "2024-07-02",
    "certification_total_count": 95,
    "certification_ratio": 41.0
  },
  "messages": {
    "suspicious": "[]",
    "information": "[]"
  }
}


```
messages
 - suspicious: 트래픽에서 발생하기 어려운 행위로 인한 메시지입니다.
 - information: 일반적으로 발생하지 않으나 정상 트래픽에서도 종종 발생할 수 있는 행위에 대한 정보를 제공합니다.

		suspicious
		 - unusual_encrypted_length_in_http/2: HTTP/2 트래픽에서 간헐적으로 발생할 수 있으나 일반적이지 않은 암호화 사이즈
		 - unknown_encrypted_length_in_http/2: HTTP/2 트래픽에서 발생하기 어려운 암호화 사이즈
		 - unusual_encryption_size: TLS 트래픽에서 발생하기 어려운 암호화 사이즈
   		 - unusual_0rtt_size: TLS 1.3 0-RTT에서 발생하기 어려운 크기의 데이터 사이즈

   		information
   		 - client_send_certificate: TLS 트래픽에서 클라이언트가 자신의 인증서를 서버로 전송
		 - multiple_duplicate_record_length: 동일한 크기의 TLS 데이터가 반복적으로 전송
		 - new_domain_in_esd: ESD 시스템에서 새롭게 확인된 도메인 정보
		 - new_csv_in_domain: 도메인에서 새롭게 확인된 CSV 정보

### lf hash

### CSV

CSV는 ClinetHello의 버전 및 확장필드로 구성된 값들을 정렬한 값으로 구성됩니다. JA3와 유사하나 확장필드의 메시지 필드 등 세부 값이 추가로 포함됩니다.

	1. 771,771
	
	2. 10,47,53,60,61,156,157,49161,49162,49171,49172,49187,49188,49191,49192
	
	3. 10:[23,24,29],11:[0],13:[513,514,515,1025,1027,1281,1283,1537],23,35,5,65281

    ①. ClientHello의 최소 버전과 버전이 명시됩니다.
    ②. ClientHello의 CipherSuites의 목록을 오름차순으로 정렬됩니다.
    ③. ClientHello의 Extension들을 오름차순으로 정렬됩니다.
	- GREASE 필드는 어떤 필드에서도 포함되지 않습니다.
	- Type: server_name (0)은 목록에서 사용되지 않습니다.
	- 아래 확장필드들은 지원되는 세부 목록이 포함되어 함께 명시됩니다. (ex. 10:[23,24,29])
		○ Type: compress_certificate (27)
		○ Type: signature_algorithms (13)
		○ Type: supported_version (43)
		○ Type: ec_point_formats (11)
  		○ Type: application_layer_protocol_negotiation (16)

### lf hash
lf는 클라이언트의 암호화 트래픽에서 발생하는 특징으로 고유한 값을 생성합니다.

### ff hash
ff는 클라이언트 또는 서버의 암호화 트래픽에서 발생하는 특징으로 고유한 값을 생성합니다.

### Certification
서버의 인증서 정보를 바탕으로 고유한 값을 생성합니다. Certification은 프로토콜 동작에 따라 일부 상황에서는 제공되지 않습니다.
