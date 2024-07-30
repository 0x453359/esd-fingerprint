# 개요
HTTP 등 암호화되지 않은 악성 행위는 문자열 기반 시그니처 등으로 대응할 수 있습니다. 공격자들은 이러한 탐지를 우회하기 위해 Google과 같은 서비스 도메인으로 위장하거나 암호화 터널링을 사용한 공격을 수행하기도 합니다.<br/>
암호화 터널링과 도메인 스푸핑이 함께 사용되는 경우에는 스트림의 페이로드 화인이 불가능하며, 이 스트림이 정상 사용자의 스트림인지 악성 행위인지 구분하기 쉽지 않습니다.

암호화 기반 공격 대응은 주로 Unknown 대응(IP, Hostname)과 블랙리스트(JA3) 방식이 많이 사용됩니다.<br/>
IP 대응은 이미 공격으로 사용되는 주소를 빠르게 식별하지만, 평가지표가 없거나 CSP의 호스팅 서비스를 중계 매체로 사용할 경우 대응이 불가능합니다.<br/><br/>
JA3는 여전히 블랙리스트 방식에서 유용하게 사용가능합니다. 그러나 JA3를 동일하게 구성하는 스푸핑 행위에서는 대응이 불가능합니다.

# ESD (Encrypted Spoofing Detection)
ESD는 Unknown 기반 탐지 시스템으로 시스템이 분석한 내용을 기반으로 희귀도 값을 제공합니다.<br/>
ESD는 악성 행위가 탐지를 회피하기 위해 일반적인 사용자의 암호화 스트림으로 스푸핑하는 행위의 탐지 정보를 제공합니다.<br/>
스푸핑 탐지에는 주요 모듈(E3C)에 의한 탐지와 암호화 트래픽에서의 일반적이지 않은 행위 정보가 추가됩니다.

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
 - suspicious: 트래픽에서 발생하기 어려운 행위로 인한 메시지
 - information: 일반적으로 발생하지 않으나 정상 트래픽에서도 종종 발생할 수 있는 행위

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
