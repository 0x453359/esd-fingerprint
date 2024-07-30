# 필요 사항
 - 매니지먼트 포트의 인터넷 연결
 - Suricata IDS 5.0 이상
 - ripgrep
 - lua 5.4 이상
 - luarocks
 - luafilesystem (luarocks install)
 - wget
 - curl
 - rsyslog 또는 동등한 대체 프로그램


## Suricata IDS

### Suricata IDS Signature
특정 시그니처를 사용하여 패킷의 매치 필요
``` bash
alert tcp-pkt any any -> any any (msg:"TLS_BASE"; flow:established,to_server; stream_size:server,<,70; content:"|16 03|"; depth:2; flowbits:set,esd_hash; sid:1000;)
alert tcp-pkt any any -> any any (msg:"SSN_ULF_BASE"; flow:established,to_server; dsize:>0; flowbits:isset,esd_hash; flowbits:isnotset,esdsh; flowbits:set,esd0; flowint:esd_base,+,1; sid:1001;)
alert tcp-pkt any any -> any any (msg:"SSN_TLS_SH"; flow:established,to_client; flowbits:isnotset,esdsh; flowbits:isset,esd0; content:"|16 03|"; depth:5;  content:"|02 00|"; distance:3; within:2; content:!"|cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c|"; flowbits:set,esdsh; sid:1002; )
alert tcp-pkt any any -> any any (msg:"SSN_TLS_HRR"; flow:established,to_client; flowbits:isset,esd0; content:"|16 03|"; content:"|02 00|"; distance:3; within:2; content:"|cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c|"; flowbits:set,tls_hrr; sid:1003; )

alert tcp-pkt any any -> any any (msg:"TLS_pkt_int"; flow:established,to_server; flowbits:isset,esdsh; dsize:>0; flowint:cpktTLS,+,1; noalert; sid:1004; )
alert tcp-pkt any any -> any any (msg:"SSN_TLS_pkt_client"; flow:established,to_server; flowbits:isset,esdsh; dsize:>0; flowint:cpktTLS,<,8; sid:1005; )
alert tcp-pkt any any -> any any (msg:"TLS_pkt_unset"; flow:established,to_server; flowbits:isset,esdsh; flowint:cpktTLS,==,7; noalert; sid:1006;)
```

### suricata.yaml
1. 패킷 수집에 사용되는 eve.json의 유효한 전송을 위해 suricata.yaml에서 일부 설정이 적용되어야 합니다.<br/>
2. eve.json에는 많은 양의 패킷 페이로드 정보가 기재되어 있습니다.<br/>
3. Stand-alone 시스템 구성이 아닌 경우, 안정적인 수신을 위해 HA 포트와 같은 독립적인 채널이 권장됩니다.<br/>

``` yaml
suricata.yaml
  # Extensible Event Format (nicknamed EVE) event log in JSON format

  - eve-log:
      enabled: yes
      filetype: syslog #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json
      facility: local5
      metadata: yes

      types:
        - alert:
            payload: no             # enable dumping payload in Base64
            payload-printable: no   # enable dumping payload in printable (lossy) format
            packet: yes              # enable dumping of packet (without stream segments)
            metadata: yes             # enable inclusion of app layer metadata with alert. Default yes
            http-body: no           # Requires metadata; enable dumping of HTTP body in Base64
            http-body-printable: no # Requires metadata; enable dumping of HTTP body in printable format
```
## rsyslog
rsyslog 등을 사용하여 /var/log/rsyslog/ 와 같은 디렉터리에 eve.json 수집 로그가 저장되어야 합니다.<br/>
``` bash
 수신포맷:
 - $template TmplMsg,"/var/log/rsyslog/%fromhost-ip%_messages_%$YEAR%-%$MONTH%-%$DAY%.log"

 전송포맷:
 - $template ES,"%msg%\n"
 - :msg, contains, "SSN_" ?TmplMsg;ES
```

# 설치
/usr/local/bin/esd/esd_install.sh

## 구동
/usr/local/bin/esd/esdd

## 로그 확인
/var/log/esd/esd_log

## 파일 설명
 - tls_esd.lua: ESD 처리 프로세스
 - esd.config: ESD 구동에 필요한 옵션 값을 기재
 - esdd: ESD 구동 및 멀티프로세싱 담당
 - esd_log_div: ESD의 패킷(eve.json) 처리 전처리 분할 과정
 - esdd_watchdog: ESD 멀티프로세스의 오류 발생 시, 프로세스의 원복
 - util*: ESD 구동 처리에 필요한 유틸리티
 - exit: ESD 서비스 종료 (watchdog 서비스는 개별 종료 필요)
