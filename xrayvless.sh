#!/bin/bash
set -e

#====== 彩色输出 (vless.sh) ======
green() { echo -e "\033[32m$1\033[0m"; }
red()   { echo -e "\033[31m$1\033[0m"; }
yellow(){ echo -e "\033[33m$1\033[0m"; }

#====== (新增) ip.sh 移植过来的彩色代码 ======
Font_B="\033[1m"
Font_D="\033[2m"
Font_I="\033[3m"
Font_U="\033[4m"
Font_Black="\033[30m"
Font_Red="\033[31m"
Font_Green="\033[32m"
Font_Yellow="\033[33m"
Font_Blue="\033[34m"
Font_Purple="\033[35m"
Font_Cyan="\033[36m"
Font_White="\033[37m"
Back_Black="\033[40m"
Back_Red="\033[41m"
Back_Green="\033[42m"
Back_Yellow="\033[43m"
Back_Blue="\033[44m"
Back_Purple="\033[45m"
Back_Cyan="\033[46m"
Back_White="\033[47m"
Font_Suffix="\033[0m"
Font_LineClear="\033[2K"
Font_LineUp="\033[1A"

#====== (新增) ip.sh 移植过来的全局变量 ======
declare -A maxmind
declare -A ipinfo
declare -A scamalytics
declare -A ipregistry
declare -A ipapi
declare -A abuseipdb
declare IP=""
declare IPhide
declare fullIP=0
declare YY="cn" # 硬编码为中文
declare -A swarn
declare -A sinfo
declare -A shead
declare -A sbasic
declare -A stype
declare -A sscore
declare -A sfactor
declare -A stail
declare ibar=0
declare bar_pid
declare ibar_step=0
declare main_pid=$$
declare PADDING=""
declare useNIC=""
declare usePROXY=""
declare CurlARG=""
declare rawgithub="https://github.com/xykt/IPQuality/raw/" # 默认Github

#====== (新增) ip.sh 移植过来的核心函数 ======

# 设置语言 (已精简，只保留中文)
set_language(){
case "$YY" in
"cn")swarn[1]="错误：不支持的参数！"
swarn[2]="错误：IP地址格式错误！"
swarn[3]="错误：未安装依赖程序，请以root执行此脚本，或者安装sudo命令！"
swarn[4]="错误：参数-4与-i/-6冲突！"
swarn[6]="错误：参数-6与-i/-4冲突！"
swarn[7]="错误：指定的网卡或出口IP不存在！"
swarn[8]="错误：指定的代理服务器不可用！"
swarn[10]="错误：输出文件已存在！"
swarn[11]="错误：输出文件不可写！"
swarn[40]="错误：IPV4不可用！"
swarn[60]="错误：IPV6不可用！"
sinfo[database]="正在检测IP数据库 "
sinfo[ldatabase]=17
shead[title]="IP质量体检报告："
shead[ver]="(移植版)"
shead[bash]="bash <(curl -sL https://Check.Place) -I"
shead[git]="https://github.com/xykt/IPQuality"
shead[time]=$(TZ="Asia/Shanghai" date +"报告时间：%Y-%m-%d %H:%M:%S CST")
shead[ltitle]=16
shead[ptime]=$(printf '%8s' '')
sbasic[title]="一、基础信息（${Font_I}Maxmind 数据库$Font_Suffix）"
sbasic[asn]="自治系统号：            "
sbasic[noasn]="未分配"
sbasic[org]="组织：                  "
sbasic[location]="坐标：                  "
sbasic[map]="地图：                  "
sbasic[city]="城市：                  "
sbasic[country]="使用地：                "
sbasic[regcountry]="注册地：                "
sbasic[continent]="洲际：                  "
sbasic[timezone]="时区：                  "
sbasic[type]="IP类型：                "
sbasic[type0]=" 原生IP "
sbasic[type1]=" 广播IP "
stype[business]="   $Back_Yellow$Font_White$Font_B 商业 $Font_Suffix   "
stype[isp]="   $Back_Green$Font_White$Font_B 家宽 $Font_Suffix   "
stype[hosting]="   $Back_Red$Font_White$Font_B 机房 $Font_Suffix   "
stype[education]="   $Back_Yellow$Font_White$Font_B 教育 $Font_Suffix   "
stype[government]="   $Back_Yellow$Font_White$Font_B 政府 $Font_Suffix   "
stype[banking]="   $Back_Yellow$Font_White$Font_B 银行 $Font_Suffix   "
stype[organization]="   $Back_Yellow$Font_White$Font_B 组织 $Font_Suffix   "
stype[military]="   $Back_Yellow$Font_White$Font_B 军队 $Font_Suffix   "
stype[library]="  $Back_Yellow$Font_White$Font_B 图书馆 $Font_Suffix  "
stype[cdn]="   $Back_Red$Font_White$Font_B CDN $Font_Suffix    "
stype[lineisp]="   $Back_Green$Font_White$Font_B 家宽 $Font_Suffix   "
stype[mobile]="   $Back_Green$Font_White$Font_B 手机 $Font_Suffix   "
stype[spider]="   $Back_Red$Font_White$Font_B 蜘蛛 $Font_Suffix   "
stype[reserved]="   $Back_Yellow$Font_White$Font_B 保留 $Font_Suffix   "
stype[other]="   $Back_Yellow$Font_White$Font_B 其他 $Font_Suffix   "
stype[title]="二、IP类型属性"
stype[db]="数据库：   "
stype[usetype]="使用类型： "
stype[comtype]="公司类型： "
sscore[verylow]="$Font_Green$Font_B极低风险$Font_Suffix"
sscore[low]="$Font_Green$Font_B低风险$Font_Suffix"
sscore[medium]="$Font_Yellow$Font_B中风险$Font_Suffix"
sscore[high]="$Font_Red$Font_B高风险$Font_Suffix"
sscore[veryhigh]="$Font_Red$Font_B极高风险$Font_Suffix"
sscore[elevated]="$Font_Yellow$Font_B较高风险$Font_Suffix"
sscore[suspicious]="$Font_Yellow$Font_B可疑IP$Font_Suffix"
sscore[risky]="$Font_Red$Font_B存在风险$Font_Suffix"
sscore[highrisk]="$Font_Red$Font_B高风险$Font_Suffix"
sscore[dos]="$Font_Red$Font_B建议封禁$Font_Suffix"
sscore[colon]="："
sscore[title]="三、风险评分"
sscore[range]="$Font_Cyan风险等级：      $Font_I$Font_White$Back_Green极低         低 $Back_Yellow      中等      $Back_Red 高         极高$Font_Suffix"
sfactor[title]="四、风险因子"
sfactor[factor]="库： "
sfactor[countrycode]="地区：  "
sfactor[proxy]="代理：  "
sfactor[tor]="Tor：   "
sfactor[vpn]="VPN：   "
sfactor[server]="服务器："
sfactor[abuser]="滥用：  "
sfactor[robot]="机器人："
sfactor[yes]="$Font_Red$Font_B 是 $Font_Suffix"
sfactor[no]="$Font_Green$Font_B 否 $Font_Suffix"
sfactor[na]="$Font_Green$Font_B 无 $Font_Suffix"
stail[stoday]="今日IP检测量："
stail[stotal]="；总检测量："
stail[thanks]="。感谢xy开源此脚本！"
stail[link]="$Font_I报告链接：$Font_U"
# (新增) 流媒体和AI检测的中文提示
sinfo[media]="正在检测流媒体服务商 "
sinfo[ai]="正在检测AI服务商 "
sinfo[lmedia]=21
sinfo[lai]=17

smedia[yes]=" $Back_Green$Font_White 解锁 $Font_Suffix  "
smedia[no]=" $Back_Red$Font_White 屏蔽 $Font_Suffix  "
smedia[bad]=" $Back_Red$Font_White 失败 $Font_Suffix  "
smedia[pending]="$Back_Yellow$Font_White 待支持 $Font_Suffix "
smedia[cn]=" $Back_Red$Font_White 中国 $Font_Suffix  "
smedia[noprem]="$Back_Red$Font_White 禁会员 $Font_Suffix "
smedia[org]="$Back_Yellow$Font_White 仅自制 $Font_Suffix "
smedia[web]="$Back_Yellow$Font_White 仅网页 $Font_Suffix "
smedia[app]=" $Back_Yellow$Font_White 仅APP $Font_Suffix "
smedia[idc]=" $Back_Yellow$Font_White 机房 $Font_Suffix  "
smedia[native]=" $Back_Green$Font_White 原生 $Font_Suffix  "
smedia[dns]="  $Back_Yellow$Font_White DNS $Font_Suffix  "
smedia[nodata]="         "
smedia[title]="五、流媒体及AI服务解锁检测"
smedia[meida]="服务商： "
smedia[status]="状态：   "
smedia[region]="地区：   "
smedia[type]="方式：   "
;;
*)echo -ne "ERROR: Language not supported!"
esac
}

# (新增) ip.sh 移植：统计
countRunTimes(){
local RunTimes=$(curl $CurlARG -s --max-time 10 "https://hits.xykt.de/ip?action=hit" 2>&1)
stail[today]=$(echo "$RunTimes"|jq '.daily')
stail[total]=$(echo "$RunTimes"|jq '.total')
}

# (新增) ip.sh 移植：进度条
show_progress_bar(){
show_progress_bar_ "$@" 1>&2
}
show_progress_bar_(){
local bar="\u280B\u2819\u2839\u2838\u283C\u2834\u2826\u2827\u2807\u280F"
local n=${#bar}
while sleep 0.1;do
if ! kill -0 $main_pid 2>/dev/null;then
echo -ne ""
exit
fi
echo -ne "\r$Font_Cyan$Font_B[$IP]# $1$Font_Cyan$Font_B$(printf '%*s' "$2" ''|tr ' ' '.') ${bar:ibar++*6%n:6} $(printf '%02d%%' $ibar_step) $Font_Suffix"
done
}
kill_progress_bar(){
kill "$bar_pid" 2>/dev/null&&echo -ne "\r"
}
# (新增) ip.sh 移植：工具函数
adapt_locale(){
local ifunicode=$(printf '\u2800')
[[ ${#ifunicode} -gt 3 ]]&&export LC_CTYPE=en_US.UTF-8 2>/dev/null
}
check_connectivity(){
local url="https://www.google.com/generate_204"
local timeout=2
local http_code
http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "$timeout" "$url" 2>/dev/null)
if [[ $http_code == "204" ]];then
rawgithub="https://github.com/xykt/IPQuality/raw/"
return 0
else
rawgithub="https://testingcf.jsdelivr.net/gh/xykt/IPQuality@"
return 1
fi
}
calculate_display_width(){
local string="$1"
local length=0
local char
for ((i=0; i<${#string}; i++));do
char=$(echo "$string"|od -An -N1 -tx1 -j $((i))|tr -d ' ')
if [ "$(printf '%d\n' 0x$char)" -gt 127 ];then
length=$((length+2))
i=$((i+1))
else
length=$((length+1))
fi
done
echo "$length"
}
calc_padding(){
local input_text="$1"
local total_width=$2
local title_length=$(calculate_display_width "$input_text")
local left_padding=$(((total_width-title_length)/2))
if [[ $left_padding -gt 0 ]];then
PADDING=$(printf '%*s' $left_padding)
else
PADDING=""
fi
}
generate_dms(){
local lat=$1
local lon=$2
if [[ -z $lat || $lat == "null" || -z $lon || $lon == "null" ]];then
echo ""
return
fi
convert_single(){
local coord=$1
local direction=$2
local fixed_coord=$(echo "$coord"|sed 's/\.$/.0/')
local degrees=$(echo "$fixed_coord"|cut -d'.' -f1)
local fractional="0.$(echo "$fixed_coord"|cut -d'.' -f2)"
local minutes=$(echo "$fractional * 60"|bc -l|cut -d'.' -f1)
local seconds_fractional="0.$(echo "$fractional * 60"|bc -l|cut -d'.' -f2)"
local seconds=$(echo "$seconds_fractional * 60"|bc -l|awk '{printf "%.0f", $1}')
echo "$degrees°$minutes′$seconds″$direction"
}
local lat_dir='N'
if [[ $(echo "$lat < 0"|bc -l) -eq 1 ]];then
lat_dir='S'
lat=$(echo "$lat * -1"|bc -l)
fi
local lon_dir='E'
if [[ $(echo "$lon < 0"|bc -l) -eq 1 ]];then
lon_dir='W'
lon=$(echo "$lon * -1"|bc -l)
fi
local lat_dms=$(convert_single $lat $lat_dir)
local lon_dms=$(convert_single $lon $lon_dir)
echo "$lon_dms, $lat_dms"
}
generate_googlemap_url(){
local lat=$1
local lon=$2
local radius=$3
if [[ -z $lat || $lat == "null" || -z $lon || $lon == "null" || -z $radius || $radius == "null" ]];then
echo ""
return
fi
local zoom_level=15
if [[ $radius -gt 1000 ]];then
zoom_level=12
elif [[ $radius -gt 500 ]];then
zoom_level=13
elif [[ $radius -gt 250 ]];then
zoom_level=14
fi
echo "https://check.place/$lat,$lon,$zoom_level,$YY"
}
hide_ipv4(){
if [[ -n $1 ]];then
IFS='.' read -r -a ip_parts <<<"$1"
IPhide="${ip_parts[0]}.${ip_parts[1]}.*.*"
else
IPhide=""
fi
}
# (新增) ip.sh 移植：你指定的 6 个数据库函数
db_maxmind(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}Maxmind $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-8-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
maxmind=()
local RESPONSE=$(curl $CurlARG -Ls -$1 -m 10 "https://ipinfo.check.place/$IP?lang=$YY")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
if [[ -z $RESPONSE ]];then
mode_lite=1
else
mode_lite=0
fi
maxmind[asn]=$(echo "$RESPONSE"|jq -r '.ASN.AutonomousSystemNumber')
maxmind[org]=$(echo "$RESPONSE"|jq -r '.ASN.AutonomousSystemOrganization')
maxmind[city]=$(echo "$RESPONSE"|jq -r '.City.Name')
maxmind[post]=$(echo "$RESPONSE"|jq -r '.City.PostalCode')
maxmind[lat]=$(echo "$RESPONSE"|jq -r '.City.Latitude')
maxmind[lon]=$(echo "$RESPONSE"|jq -r '.City.Longitude')
maxmind[rad]=$(echo "$RESPONSE"|jq -r '.City.AccuracyRadius')
maxmind[continentcode]=$(echo "$RESPONSE"|jq -r '.City.Continent.Code')
maxmind[continent]=$(echo "$RESPONSE"|jq -r '.City.Continent.Name')
maxmind[citycountrycode]=$(echo "$RESPONSE"|jq -r '.City.Country.IsoCode')
maxmind[citycountry]=$(echo "$RESPONSE"|jq -r '.City.Country.Name')
maxmind[timezone]=$(echo "$RESPONSE"|jq -r '.City.Location.TimeZone')
maxmind[subcode]=$(echo "$RESPONSE"|jq -r 'if .City.Subdivisions | length > 0 then .City.Subdivisions[0].IsoCode else "N/A" end')
maxmind[sub]=$(echo "$RESPONSE"|jq -r 'if .City.Subdivisions | length > 0 then .City.Subdivisions[0].Name else "N/A" end')
maxmind[countrycode]=$(echo "$RESPONSE"|jq -r '.Country.IsoCode')
maxmind[country]=$(echo "$RESPONSE"|jq -r '.Country.Name')
maxmind[regcountrycode]=$(echo "$RESPONSE"|jq -r '.Country.RegisteredCountry.IsoCode')
maxmind[regcountry]=$(echo "$RESPONSE"|jq -r '.Country.RegisteredCountry.Name')
if [[ $YY != "en" ]];then
local backup_response=$(curl $CurlARG -s -$1 -m 10 "https://ipinfo.check.place/$IP?lang=en")
[[ ${maxmind[asn]} == "null" ]]&&maxmind[asn]=$(echo "$backup_response"|jq -r '.ASN.AutonomousSystemNumber')
[[ ${maxmind[org]} == "null" ]]&&maxmind[org]=$(echo "$backup_response"|jq -r '.ASN.AutonomousSystemOrganization')
[[ ${maxmind[city]} == "null" ]]&&maxmind[city]=$(echo "$backup_response"|jq -r '.City.Name')
[[ ${maxmind[post]} == "null" ]]&&maxmind[post]=$(echo "$backup_response"|jq -r '.City.PostalCode')
[[ ${maxmind[lat]} == "null" ]]&&maxmind[lat]=$(echo "$backup_response"|jq -r '.City.Latitude')
[[ ${maxmind[lon]} == "null" ]]&&maxmind[lon]=$(echo "$backup_response"|jq -r '.City.Longitude')
[[ ${maxmind[rad]} == "null" ]]&&maxmind[rad]=$(echo "$backup_response"|jq -r '.City.AccuracyRadius')
[[ ${maxmind[continentcode]} == "null" ]]&&maxmind[continentcode]=$(echo "$backup_response"|jq -r '.City.Continent.Code')
[[ ${maxmind[continent]} == "null" ]]&&maxmind[continent]=$(echo "$backup_response"|jq -r '.City.Continent.Name')
[[ ${maxmind[citycountrycode]} == "null" ]]&&maxmind[citycountrycode]=$(echo "$backup_response"|jq -r '.City.Country.IsoCode')
[[ ${maxmind[citycountry]} == "null" ]]&&maxmind[citycountry]=$(echo "$backup_response"|jq -r '.City.Country.Name')
[[ ${maxmind[timezone]} == "null" ]]&&maxmind[timezone]=$(echo "$backup_response"|jq -r '.City.Location.TimeZone')
[[ ${maxmind[subcode]} == "null" ]]&&maxmind[subcode]=$(echo "$backup_response"|jq -r 'if .City.Subdivisions | length > 0 then .City.Subdivisions[0].IsoCode else "N/A" end')
[[ ${maxmind[sub]} == "null" ]]&&maxmind[sub]=$(echo "$backup_response"|jq -r 'if .City.Subdivisions | length > 0 then .City.Subdivisions[0].Name else "N/A" end')
[[ ${maxmind[countrycode]} == "null" ]]&&maxmind[countrycode]=$(echo "$backup_response"|jq -r '.Country.IsoCode')
[[ ${maxmind[country]} == "null" ]]&&maxmind[country]=$(echo "$backup_response"|jq -r '.Country.Name')
[[ ${maxmind[regcountrycode]} == "null" ]]&&maxmind[regcountrycode]=$(echo "$backup_response"|jq -r '.Country.RegisteredCountry.IsoCode')
[[ ${maxmind[regcountry]} == "null" ]]&&maxmind[regcountry]=$(echo "$backup_response"|jq -r '.Country.RegisteredCountry.Name')
fi
if [[ ${maxmind[lat]} != "null" && ${maxmind[lon]} != "null" ]];then
maxmind[dms]=$(generate_dms "${maxmind[lat]}" "${maxmind[lon]}")
maxmind[map]=$(generate_googlemap_url "${maxmind[lat]}" "${maxmind[lon]}" "${maxmind[rad]}")
else
maxmind[dms]="null"
maxmind[map]="null"
fi
}
db_ipinfo(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}IPinfo $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-7-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ipinfo=()
local RESPONSE=$(curl $CurlARG -Ls -m 10 "https://ipinfo.io/widget/demo/$IP")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
ipinfo[usetype]=$(echo "$RESPONSE"|jq -r '.data.asn.type')
ipinfo[comtype]=$(echo "$RESPONSE"|jq -r '.data.company.type')
shopt -s nocasematch
case ${ipinfo[usetype]} in
"business")ipinfo[susetype]="${stype[business]}"
;;
"isp")ipinfo[susetype]="${stype[isp]}"
;;
"hosting")ipinfo[susetype]="${stype[hosting]}"
;;
"education")ipinfo[susetype]="${stype[education]}"
;;
*)ipinfo[susetype]="${stype[other]}"
esac
case ${ipinfo[comtype]} in
"business")ipinfo[scomtype]="${stype[business]}"
;;
"isp")ipinfo[scomtype]="${stype[isp]}"
;;
"hosting")ipinfo[scomtype]="${stype[hosting]}"
;;
"education")ipinfo[scomtype]="${stype[education]}"
;;
*)ipinfo[scomtype]="${stype[other]}"
esac
shopt -u nocasematch
ipinfo[countrycode]=$(echo "$RESPONSE"|jq -r '.data.country')
ipinfo[proxy]=$(echo "$RESPONSE"|jq -r '.data.privacy.proxy')
ipinfo[tor]=$(echo "$RESPONSE"|jq -r '.data.privacy.tor')
ipinfo[vpn]=$(echo "$RESPONSE"|jq -r '.data.privacy.vpn')
ipinfo[server]=$(echo "$RESPONSE"|jq -r '.data.privacy.hosting')
local ISO3166=$(curl -sL -m 10 "${rawgithub}main/ref/iso3166.json")
ipinfo[asn]=$(echo "$RESPONSE"|jq -r '.data.asn.asn'|sed 's/^AS//')
ipinfo[org]=$(echo "$RESPONSE"|jq -r '.data.asn.name')
ipinfo[city]=$(echo "$RESPONSE"|jq -r '.data.city')
ipinfo[post]=$(echo "$RESPONSE"|jq -r '.data.postal')
ipinfo[timezone]=$(echo "$RESPONSE"|jq -r '.data.timezone')
local tmp_str=$(echo "$RESPONSE"|jq -r '.data.loc')
ipinfo[lat]=$(echo "$tmp_str"|cut -d',' -f1)
ipinfo[lon]=$(echo "$tmp_str"|cut -d',' -f2)
ipinfo[countrycode]=$(echo "$RESPONSE"|jq -r '.data.country')
ipinfo[country]=$(echo "$ISO3166"|jq --arg code "${ipinfo[countrycode]}" -r '.[] | select(.["alpha-2"] == $code) | .name')
ipinfo[continent]=$(echo "$ISO3166"|jq --arg code "${ipinfo[countrycode]}" -r '.[] | select(.["alpha-2"] == $code) | .region')
ipinfo[regcountrycode]=$(echo "$RESPONSE"|jq -r '.data.abuse.country')
ipinfo[regcountry]=$(echo "$ISO3166"|jq --arg code "${ipinfo[regcountrycode]}" -r '.[] | select(.["alpha-2"] == $code) | .name')
if [[ ${ipinfo[lat]} != "null" && ${ipinfo[lon]} != "null" ]];then
ipinfo[dms]=$(generate_dms "${ipinfo[lat]}" "${ipinfo[lon]}")
ipinfo[map]=$(generate_googlemap_url "${ipinfo[lat]}" "${ipinfo[lon]}" "1001")
else
ipinfo[dms]="null"
ipinfo[map]="null"
fi
}
db_scamalytics(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}Scamalytics $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-12-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
scamalytics=()
local RESPONSE=$(curl $CurlARG -sL -$1 -m 10 "https://ipinfo.check.place/$IP?db=scamalytics")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
scamalytics[countrycode]=$(echo "$RESPONSE"|jq -r '.external_datasources.maxmind_geolite2.ip_country_code')
scamalytics[proxy]=$(echo "$RESPONSE"|jq -r '.external_datasources.firehol.is_proxy')
scamalytics[tor]=$(echo "$RESPONSE"|jq -r '.external_datasources.x4bnet.is_tor')
scamalytics[vpn]=$(echo "$RESPONSE"|jq -r '.scamalytics.scamalytics_proxy.is_vpn')
scamalytics[server]=$(echo "$RESPONSE"|jq -r '.scamalytics.scamalytics_proxy.is_datacenter')
scamalytics[abuser]=$(echo "$RESPONSE"|jq -r '.scamalytics.is_blacklisted_external')
scamalytics[robot1]=$(echo "$RESPONSE"|jq -r '.external_datasources.x4bnet.is_blacklisted_spambot')
scamalytics[robot2]=$(echo "$RESPONSE"|jq -r '.external_datasources.x4bnet.is_bot_operamini')
scamalytics[robot3]=$(echo "$RESPONSE"|jq -r '.external_datasources.x4bnet.is_bot_semrush')
[[ ${scamalytics[robot1]} == "true" || ${scamalytics[robot2]} == "true" || ${scamalytics[robot3]} == "true" ]]&&scamalytics[robot]="true"
[[ ${scamalytics[robot1]} == "false" && ${scamalytics[robot2]} == "false" && ${scamalytics[robot3]} == "false" ]]&&scamalytics[robot]="false"
scamalytics[score]=$(echo "$RESPONSE"|jq -r '.scamalytics.scamalytics_score')
if [[ ${scamalytics[score]} -lt 20 ]];then
scamalytics[risk]="${sscore[low]}"
elif [[ ${scamalytics[score]} -lt 60 ]];then
scamalytics[risk]="${sscore[medium]}"
elif [[ ${scamalytics[score]} -lt 90 ]];then
scamalytics[risk]="${sscore[high]}"
elif [[ ${scamalytics[score]} -ge 90 ]];then
scamalytics[risk]="${sscore[veryhigh]}"
fi
}
db_ipregistry(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}ipregistry $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-11-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ipregistry=()
local RESPONSE=$(curl $CurlARG -sL -$1 -m 10 "https://ipinfo.check.place/$IP?db=ipregistry")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
ipregistry[usetype]=$(echo "$RESPONSE"|jq -r '.connection.type')
ipregistry[comtype]=$(echo "$RESPONSE"|jq -r '.company.type')
shopt -s nocasematch
case ${ipregistry[usetype]} in
"business")ipregistry[susetype]="${stype[business]}"
;;
"isp")ipregistry[susetype]="${stype[isp]}"
;;
"hosting")ipregistry[susetype]="${stype[hosting]}"
;;
"education")ipregistry[susetype]="${stype[education]}"
;;
"government")ipregistry[susetype]="${stype[government]}"
;;
*)ipregistry[susetype]="${stype[other]}"
esac
case ${ipregistry[comtype]} in
"business")ipregistry[scomtype]="${stype[business]}"
;;
"isp")ipregistry[scomtype]="${stype[isp]}"
;;
"hosting")ipregistry[scomtype]="${stype[hosting]}"
;;
"education")ipregistry[scomtype]="${stype[education]}"
;;
"government")ipregistry[scomtype]="${stype[government]}"
;;
*)ipregistry[scomtype]="${stype[other]}"
esac
shopt -u nocasematch
ipregistry[countrycode]=$(echo "$RESPONSE"|jq -r '.location.country.code')
ipregistry[proxy]=$(echo "$RESPONSE"|jq -r '.security.is_proxy')
ipregistry[tor1]=$(echo "$RESPONSE"|jq -r '.security.is_tor')
ipregistry[tor2]=$(echo "$RESPONSE"|jq -r '.security.is_tor_exit')
[[ ${ipregistry[tor1]} == "true" || ${ipregistry[tor2]} == "true" ]]&&ipregistry[tor]="true"
[[ ${ipregistry[tor1]} == "false" && ${ipregistry[tor2]} == "false" ]]&&ipregistry[tor]="false"
ipregistry[vpn]=$(echo "$RESPONSE"|jq -r '.security.is_vpn')
ipregistry[server]=$(echo "$RESPONSE"|jq -r '.security.is_cloud_provider')
ipregistry[abuser]=$(echo "$RESPONSE"|jq -r '.security.is_abuser')
}
db_ipapi(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}ipapi $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-6-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
ipapi=()
local RESPONSE=$(curl $CurlARG -sL -m 10 "https://api.ipapi.is/?q=$IP")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
ipapi[usetype]=$(echo "$RESPONSE"|jq -r '.asn.type')
ipapi[comtype]=$(echo "$RESPONSE"|jq -r '.company.type')
shopt -s nocasematch
case ${ipapi[usetype]} in
"business")ipapi[susetype]="${stype[business]}"
;;
"isp")ipapi[susetype]="${stype[isp]}"
;;
"hosting")ipapi[susetype]="${stype[hosting]}"
;;
"education")ipapi[susetype]="${stype[education]}"
;;
"government")ipapi[susetype]="${stype[government]}"
;;
"banking")ipapi[susetype]="${stype[banking]}"
;;
*)ipapi[susetype]="${stype[other]}"
esac
case ${ipapi[comtype]} in
"business")ipapi[scomtype]="${stype[business]}"
;;
"isp")ipapi[scomtype]="${stype[isp]}"
;;
"hosting")ipapi[scomtype]="${stype[hosting]}"
;;
"education")ipapi[scomtype]="${stype[education]}"
;;
"government")ipapi[scomtype]="${stype[government]}"
;;
"banking")ipapi[scomtype]="${stype[banking]}"
;;
*)ipapi[scomtype]="${stype[other]}"
esac
[[ -z $RESPONSE ]]&&return 1
ipapi[scoretext]=$(echo "$RESPONSE"|jq -r '.company.abuser_score')
ipapi[scorenum]=$(echo "${ipapi[scoretext]}"|awk '{print $1}')
ipapi[risktext]=$(echo "${ipapi[scoretext]}"|awk -F'[()]' '{print $2}')
ipapi[score]=$(awk "BEGIN {printf \"%.2f%%\", ${ipapi[scorenum]} * 100}")
case ${ipapi[risktext]} in
"Very Low")ipapi[risk]="${sscore[verylow]}"
;;
"Low")ipapi[risk]="${sscore[low]}"
;;
"Elevated")ipapi[risk]="${sscore[elevated]}"
;;
"High")ipapi[risk]="${sscore[high]}"
;;
"Very High")ipapi[risk]="${sscore[veryhigh]}"
esac
shopt -u nocasematch
ipapi[countrycode]=$(echo "$RESPONSE"|jq -r '.location.country_code')
ipapi[proxy]=$(echo "$RESPONSE"|jq -r '.is_proxy')
ipapi[tor]=$(echo "$RESPONSE"|jq -r '.is_tor')
ipapi[vpn]=$(echo "$RESPONSE"|jq -r '.is_vpn')
ipapi[server]=$(echo "$RESPONSE"|jq -r '.is_datacenter')
ipapi[abuser]=$(echo "$RESPONSE"|jq -r '.is_abuser')
ipapi[robot]=$(echo "$RESPONSE"|jq -r '.is_crawler')
}
db_abuseipdb(){
local temp_info="$Font_Cyan$Font_B${sinfo[database]}${Font_I}AbuseIPDB $Font_Suffix"
((ibar_step+=3))
show_progress_bar "$temp_info" $((40-10-${sinfo[ldatabase]}))&
bar_pid="$!"&&disown "$bar_pid"
trap "kill_progress_bar" RETURN
abuseipdb=()
local RESPONSE=$(curl $CurlARG -sL -$1 -m 10 "https://ipinfo.check.place/$IP?db=abuseipdb")
echo "$RESPONSE"|jq . >/dev/null 2>&1||RESPONSE=""
abuseipdb[usetype]=$(echo "$RESPONSE"|jq -r '.data.usageType')
shopt -s nocasematch
case ${abuseipdb[usetype]} in
"Commercial")abuseipdb[susetype]="${stype[business]}"
;;
"Data Center/Web Hosting/Transit")abuseipdb[susetype]="${stype[hosting]}"
;;
"University/College/School")abuseipdb[susetype]="${stype[education]}"
;;
"Government")abuseipdb[susetype]="${stype[government]}"
;;
"banking")abuseipdb[susetype]="${stype[banking]}"
;;
"Organization")abuseipdb[susetype]="${stype[organization]}"
;;
"Military")abuseipdb[susetype]="${stype[military]}"
;;
"Library")abuseipdb[susetype]="${stype[library]}"
;;
"Content Delivery Network")abuseipdb[susetype]="${stype[cdn]}"
;;
"Fixed Line ISP")abuseipdb[susetype]="${stype[lineisp]}"
;;
"Mobile ISP")abuseipdb[susetype]="${stype[mobile]}"
;;
"Search Engine Spider")abuseipdb[susetype]="${stype[spider]}"
;;
"Reserved")abuseipdb[susetype]="${stype[reserved]}"
;;
*)abuseipdb[susetype]="${stype[other]}"
esac
shopt -u nocasematch
abuseipdb[score]=$(echo "$RESPONSE"|jq -r '.data.abuseConfidenceScore')
if [[ ${abuseipdb[score]} -lt 25 ]];then
abuseipdb[risk]="${sscore[low]}"
elif [[ ${abuseipdb[score]} -lt 75 ]];then
abuseipdb[risk]="${sscore[high]}"
elif [[ ${abuseipdb[score]} -ge 75 ]];then
abuseipdb[risk]="${sscore[dos]}"
fi
}
# (新增) ip.sh 移植：打印函数 (已精简)
show_head(){
echo -ne "\r$(printf '%72s'|tr ' ' '#')\n"
if [ $fullIP -eq 1 ];then
calc_padding "$(printf '%*s' "${shead[ltitle]}" '')$IP" 72
echo -ne "\r$PADDING$Font_B${shead[title]}$Font_Cyan$IP$Font_Suffix\n"
else
calc_padding "$(printf '%*s' "${shead[ltitle]}" '')$IPhide" 72
echo -ne "\r$PADDING$Font_B${shead[title]}$Font_Cyan$IPhide$Font_Suffix\n"
fi
calc_padding "${shead[git]}" 72
echo -ne "\r$PADDING$Font_U${shead[git]}$Font_Suffix\n"
calc_padding "${shead[bash]}" 72
echo -ne "\r$PADDING${shead[bash]}\n"
echo -ne "\r${shead[ptime]}${shead[time]}  ${shead[ver]}\n"
echo -ne "\r$(printf '%72s'|tr ' ' '#')\n"
}
show_basic(){
echo -ne "\r${sbasic[title]}\n"
if [[ -n ${maxmind[asn]} && ${maxmind[asn]} != "null" ]];then
echo -ne "\r$Font_Cyan${sbasic[asn]}${Font_Green}AS${maxmind[asn]}$Font_Suffix\n"
echo -ne "\r$Font_Cyan${sbasic[org]}$Font_Green${maxmind[org]}$Font_Suffix\n"
else
echo -ne "\r$Font_Cyan${sbasic[asn]}${sbasic[noasn]}$Font_Suffix\n"
fi
if [[ ${maxmind[dms]} != "null" && ${maxmind[map]} != "null" ]];then
echo -ne "\r$Font_Cyan${sbasic[location]}$Font_Green${maxmind[dms]}$Font_Suffix\n"
echo -ne "\r$Font_Cyan${sbasic[map]}$Font_U$Font_Green${maxmind[map]}$Font_Suffix\n"
fi
local city_info=""
if [[ -n ${maxmind[sub]} && ${maxmind[sub]} != "null" ]];then
city_info+="${maxmind[sub]}"
fi
if [[ -n ${maxmind[city]} && ${maxmind[city]} != "null" ]];then
[[ -n $city_info ]]&&city_info+=", "
city_info+="${maxmind[city]}"
fi
if [[ -n ${maxmind[post]} && ${maxmind[post]} != "null" ]];then
[[ -n $city_info ]]&&city_info+=", "
city_info+="${maxmind[post]}"
fi
if [[ -n $city_info ]];then
echo -ne "\r$Font_Cyan${sbasic[city]}$Font_Green$city_info$Font_Suffix\n"
fi
if [[ -n ${maxmind[countrycode]} && ${maxmind[countrycode]} != "null" ]];then
echo -ne "\r$Font_Cyan${sbasic[country]}$Font_Green[${maxmind[countrycode]}]${maxmind[country]}$Font_Suffix"
if [[ -n ${maxmind[continentcode]} && ${maxmind[continentcode]} != "null" ]];then
echo -ne "$Font_Green, [${maxmind[continentcode]}]${maxmind[continent]}$Font_Suffix\n"
else
echo -ne "\n"
fi
elif [[ -n ${maxmind[continentcode]} && ${maxmind[continentcode]} != "null" ]];then
echo -ne "\r$Font_Cyan${sbasic[continent]}$Font_Green[${maxmind[continentcode]}]${maxmind[continent]}$Font_Suffix\n"
fi
if [[ -n ${maxmind[regcountrycode]} && ${maxmind[regcountrycode]} != "null" ]];then
echo -ne "\r$Font_Cyan${sbasic[regcountry]}$Font_Green[${maxmind[regcountrycode]}]${maxmind[regcountry]}$Font_Suffix\n"
fi
if [[ -n ${maxmind[timezone]} && ${maxmind[timezone]} != "null" ]];then
echo -ne "\r$Font_Cyan${sbasic[timezone]}$Font_Green${maxmind[timezone]}$Font_Suffix\n"
fi
if [[ -n ${maxmind[countrycode]} && ${maxmind[countrycode]} != "null" ]];then
if [ "${maxmind[countrycode]}" == "${maxmind[regcountrycode]}" ];then
echo -ne "\r$Font_Cyan${sbasic[type]}$Back_Green$Font_B$Font_White${sbasic[type0]}$Font_Suffix\n"
else
echo -ne "\r$Font_Cyan${sbasic[type]}$Back_Red$Font_B$Font_White${sbasic[type1]}$Font_Suffix\n"
fi
fi
}
show_type(){
echo -ne "\r${stype[title]}\n"
# (已修改) 只保留你需要的 4 个
echo -ne "\r$Font_Cyan${stype[db]}$Font_I   IPinfo    ipregistry    ipapi    AbuseIPDB $Font_Suffix\n"
# (已修改) 只保留你需要的 4 个
echo -ne "\r$Font_Cyan${stype[usetype]}$Font_Suffix${ipinfo[susetype]}${ipregistry[susetype]}${ipapi[susetype]}${abuseipdb[susetype]}\n"
echo -ne "\r$Font_Cyan${stype[comtype]}$Font_Suffix${ipinfo[scomtype]}${ipregistry[scomtype]}${ipapi[scomtype]}\n"
}
sscore_text(){
local text="$1"
local p2=$2
local p3=$3
local p4=$4
local p5=$5
local p6=$6
local tmplen
local tmp
if ((p2>=p4));then
tmplen=$((49+15*(p2-p4)/(p5-p4)-p6))
elif ((p2>=p3));then
tmplen=$((33+16*(p2-p3)/(p4-p3)-p6))
elif ((p2>=0));then
tmplen=$((17+16*p2/p3-p6))
else
tmplen=0
fi
tmp=$(printf '%*s' $tmplen '')
local total_length=${#tmp}
local text_length=${#text}
local tmp1="${tmp:1:total_length-text_length}$text|"
sscore[text1]="${tmp1:1:16-p6}"
sscore[text2]="${tmp1:17-p6:16}"
sscore[text3]="${tmp1:33-p6:16}"
sscore[text4]="${tmp1:49-p6}"
}
show_score(){
echo -ne "\r${sscore[title]}\n"
echo -ne "\r${sscore[range]}\n"
# (已修改) 只保留你需要的 3 个
# if [[ -n ${ip2location[score]} && $mode_lite -eq 0 ]];then
# sscore_text "${ip2location[score]}" ${ip2location[score]} 33 66 99 13
# echo -ne "\r${Font_Cyan}IP2Location${sscore[colon]}$Font_White$Font_B${sscore[text1]}$Back_Green${sscore[text2]}$Back_Yellow${sscore[text3]}$Back_Red${sscore[text4]}$Font_Suffix${ip2location[risk]}\n"
# fi
if [[ -n ${scamalytics[score]} ]];then
sscore_text "${scamalytics[score]}" ${scamalytics[score]} 20 60 100 13
echo -ne "\r${Font_Cyan}Scamalytics${sscore[colon]}$Font_White$Font_B${sscore[text1]}$Back_Green${sscore[text2]}$Back_Yellow${sscore[text3]}$Back_Red${sscore[text4]}$Font_Suffix${scamalytics[risk]}\n"
fi
if [[ -n ${ipapi[score]} ]];then
local tmp_score=$(echo "${ipapi[scorenum]} * 10000 / 1"|bc)
sscore_text "${ipapi[score]}" $tmp_score 85 300 10000 7
echo -ne "\r${Font_Cyan}ipapi${sscore[colon]}$Font_White$Font_B${sscore[text1]}$Back_Green${sscore[text2]}$Back_Yellow${sscore[text3]}$Back_Red${sscore[text4]}$Font_Suffix${ipapi[risk]}\n"
fi
sscore_text "${abuseipdb[score]}" ${abuseipdb[score]} 25 25 100 11
[[ -n ${abuseipdb[score]} ]]&&echo -ne "\r${Font_Cyan}AbuseIPDB${sscore[colon]}$Font_White$Font_B${sscore[text1]}$Back_Green${sscore[text2]}$Back_Yellow${sscore[text3]}$Back_Red${sscore[text4]}$Font_Suffix${abuseipdb[risk]}\n"
# if [ -n "${ipqs[score]}" ]&&[ "${ipqs[score]}" != "null" ];then
# sscore_text "${ipqs[score]}" ${ipqs[score]} 75 85 100 6
# echo -ne "\r${Font_Cyan}IPQS${sscore[colon]}$Font_White$Font_B${sscore[text1]}$Back_Green${sscore[text2]}$Back_Yellow${sscore[text3]}$Back_Red${sscore[text4]}$Font_Suffix${ipqs[risk]}\n"
# fi
# sscore_text " " ${dbip[score]} 33 66 100 7
# [[ -n ${dbip[risk]} ]]&&echo -ne "\r${Font_Cyan}DB-IP${sscore[colon]}$Font_White$Font_B${sscore[text1]}$Back_Green${sscore[text2]}$Back_Yellow${sscore[text3]}$Back_Red${sscore[text4]}$Font_Suffix${dbip[risk]}\n"
}
# (已修改) 精简为 4 个
format_factor(){
local tmp_txt="  "
if [[ $1 == "true" ]];then
tmp_txt+="${sfactor[yes]}"
elif [[ $1 == "false" ]];then
tmp_txt+="${sfactor[no]}"
elif [ ${#1} -eq 2 ];then
tmp_txt+="$Font_Green[$1]$Font_Suffix"
else
tmp_txt+="${sfactor[na]}"
fi
tmp_txt+="    "
if [[ $2 == "true" ]];then
tmp_txt+="${sfactor[yes]}"
elif [[ $2 == "false" ]];then
tmp_txt+="${sfactor[no]}"
elif [ ${#2} -eq 2 ];then
tmp_txt+="$Font_Green[$2]$Font_Suffix"
else
tmp_txt+="${sfactor[na]}"
fi
tmp_txt+="    "
if [[ $3 == "true" ]];then
tmp_txt+="${sfactor[yes]}"
elif [[ $3 == "false" ]];then
tmp_txt+="${sfactor[no]}"
elif [ ${#3} -eq 2 ];then
tmp_txt+="$Font_Green[$3]$Font_Suffix"
else
tmp_txt+="${sfactor[na]}"
fi
tmp_txt+="    "
if [[ $4 == "true" ]];then
tmp_txt+="${sfactor[yes]}"
elif [[ $4 == "false" ]];then
tmp_txt+="${sfactor[no]}"
elif [ ${#4} -eq 2 ];then
tmp_txt+="$Font_Green[$4]$Font_Suffix"
else
tmp_txt+="${sfactor[na]}"
fi
echo "$tmp_txt"
}
# (已修改) 精简为 4 个
show_factor(){
local tmp_factor=""
echo -ne "\r${sfactor[title]}\n"
echo -ne "\r$Font_Cyan${sfactor[factor]}${Font_I}   ipapi    ipregistry Scamalytics   IPinfo $Font_Suffix\n"
tmp_factor=$(format_factor "${ipapi[countrycode]}" "${ipregistry[countrycode]}" "${scamalytics[countrycode]}" "${ipinfo[countrycode]}")
echo -ne "\r$Font_Cyan${sfactor[countrycode]}$Font_Suffix$tmp_factor\n"
tmp_factor=$(format_factor "${ipapi[proxy]}" "${ipregistry[proxy]}" "${scamalytics[proxy]}" "${ipinfo[proxy]}")
echo -ne "\r$Font_Cyan${sfactor[proxy]}$Font_Suffix$tmp_factor\n"
tmp_factor=$(format_factor "${ipapi[tor]}" "${ipregistry[tor]}" "${scamalytics[tor]}" "${ipinfo[tor]}")
echo -ne "\r$Font_Cyan${sfactor[tor]}$Font_Suffix$tmp_factor\n"
tmp_factor=$(format_factor "${ipapi[vpn]}" "${ipregistry[vpn]}" "${scamalytics[vpn]}" "${ipinfo[vpn]}")
echo -ne "\r$Font_Cyan${sfactor[vpn]}$Font_Suffix$tmp_factor\n"
tmp_factor=$(format_factor "${ipapi[server]}" "${ipregistry[server]}" "${scamalytics[server]}" "${ipinfo[server]}")
echo -ne "\r$Font_Cyan${sfactor[server]}$Font_Suffix$tmp_factor\n"
tmp_factor=$(format_factor "${ipapi[abuser]}" "${ipregistry[abuser]}" "${scamalytics[abuser]}" "${ipinfo[abuser]}")
echo -ne "\r$Font_Cyan${sfactor[abuser]}$Font_Suffix$tmp_factor\n"
tmp_factor=$(format_factor "${ipapi[robot]}" "${ipregistry[robot]}" "${scamalytics[robot]}" "${ipinfo[robot]}")
echo -ne "\r$Font_Cyan${sfactor[robot]}$Font_Suffix$tmp_factor\n"
}
show_tail(){
echo -ne "\r$(printf '%72s'|tr ' ' '=')\n"
echo -ne "\r$Font_I${stail[stoday]}${stail[today]}${stail[stotal]}${stail[total]}${stail[thanks]} $Font_Suffix\n"
echo -e ""
}
#====== vless.sh 原始函数 ======

# 1. 安装 VLESS + Reality
install_vless_reality() {
    green "--- 1. 安装 VLESS + Reality ---"
    
    read -p "请输入监听端口（如 443）: " PORT
    read -p "请输入备注名称（将作为用户标识）: " REMARK

    green "[1/5] 安装依赖 (curl, wget, xz-utils, jq)..."
    if command -v apt &> /dev/null; then
        apt update -y >/dev/null 2>&1
        apt install -y curl wget xz-utils jq >/dev/null 2>&1
    else
        yellow "警告：非 apt 系统，请确保已手动安装 curl, wget, xz-utils, jq"
    fi

    green "[2/5] 安装 Xray..."
    bash <(curl -Ls https://github.com/XTLS/Xray-install/raw/main/install-release.sh)

    XRAY_BIN=$(command -v xray || echo "/usr/local/bin/xray")
    [ ! -x "$XRAY_BIN" ] && red "❌ 未找到 xray" && return 1

    CONFIG_PATH="/usr/local/etc/xray/config.json"
    mkdir -p $(dirname $CONFIG_PATH)

    green "[3/5] 生成 X25519 密钥..."
    X25519_OUT="$("$XRAY_BIN" x25519 2>&1)"

    # (使用你修正后的正确逻辑)
    PRIVATE_KEY=$(echo "$X25519_OUT" | grep -i "PrivateKey" | awk '{print $2}')
    PUBLIC_KEY=$(echo "$X25519_OUT" | grep -i "Password"   | awk '{print $2}')

    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        red "❌ X25519 密钥生成失败，请检查 Xray 可执行文件"
        red "原始输出: $X25519_OUT"
        return 1
    fi

    green "私钥: $PRIVATE_KEY"
    green "公钥 (Password): $PUBLIC_KEY"

    UUID=$(cat /proc/sys/kernel/random/uuid)
    SHORT_ID=$(head -c 8 /dev/urandom | xxd -p)
    SNI="www.cloudflare.com"

    green "[4/5] 写入配置文件..."
    cat > $CONFIG_PATH <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": $PORT,
    "protocol": "vless",
    "settings": {
      "clients": [{
        "id": "$UUID",
        "email": "$REMARK"
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "$SNI:443",
        "xver": 0,
        "serverNames": ["$SNI"],
        "privateKey": "$PRIVATE_KEY",
        "shortIds": ["$SHORT_ID"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF

    green "[5/5] 启动 Xray 并设置开机自启..."
    systemctl daemon-reload
    systemctl enable xray
    systemctl restart xray

    IP=$(curl -s ipv4.ip.sb || curl -s ifconfig.me)
    
    VLESS_LINK="vless://$UUID@$IP:$PORT?type=tcp&security=reality&sni=$SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID#$REMARK"

    green "====== VLESS Reality 节点链接 ======"
    echo "$VLESS_LINK"
    green "===================================="
    read -rp "安装完成，按任意键返回菜单..."
}

# 2. 进行测速
run_speedtest() {
    green "--- 2. 进行 Ookla Speedtest 测速 ---"
    green "正在下载并运行 Ookla Speedtest..."
    local speedtest_tgz="ookla-speedtest-1.2.0-linux-x86_64.tgz"
    wget -q -O $speedtest_tgz https://install.speedtest.net/app/cli/$speedtest_tgz
    tar -zxf $speedtest_tgz
    chmod +x speedtest
    ./speedtest --accept-license --accept-gdpr
    rm -f speedtest speedtest.5 speedtest.md $speedtest_tgz
    read -rp "测速完成，按任意键返回菜单..."
}

# 3. ip质量检测 (修改为调用移植来的函数)
run_ip_quality_check() {
    green "--- 3. ip质量检测---"
    
    # 获取 IP
    IP=$(curl -s ipv4.ip.sb || curl -s ifconfig.me)
    if [ -z "$IP" ]; then
        red "❌ 自动获取公网 IP 失败"
        read -rp "按任意键返回菜单..."
        return
    fi
    
    # (新增) 调用移植来的函数
    ibar_step=0
    clear
    hide_ipv4 $IP
    countRunTimes
    
    # (已精简) 只调用你需要的 6 个
    db_maxmind 4
    db_ipinfo
    db_scamalytics 4
    db_ipregistry 4
    db_ipapi
    db_abuseipdb 4
    
    echo -ne "$Font_LineClear" 1>&2
    
    # (已精简) 只打印你需要的部分
    show_head
    show_basic
    show_type
    show_score
    show_factor
    show_tail

    green "检测完成。"
    read -rp "按任意键返回菜单..."
}
run_streaming_check() {
    green "--- 4. 流媒体解锁检测 (移植版, 新格式) ---"
    
    # 只需要 UA 和 Cookie 变量
    declare UA_Browser
    declare Media_Cookie

    # (移植) 所有需要的辅助函数，定义为本地函数
    
    # --- DNS/IP 辅助函数 (保持不变) ---
    check_ip_valide(){ local IPPattern='^(\<([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\>\.){3}\<([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\>$'; IP="$1"; if [[ $IP =~ $IPPattern ]];then return 0; else return 1; fi; }; calc_ip_net(){ sip="$1"; snetmask="$2"; check_ip_valide "$sip"; if [ $? -ne 0 ];then echo ""; return 1; fi; local ipFIELD1=$(echo "$sip"|cut -d. -f1); local ipFIELD2=$(echo "$sip"|cut -d. -f2); local ipFIELD3=$(echo "$sip"|cut -d. -f3); local ipFIELD4=$(echo "$sip"|cut -d. -f4); local netmaskFIELD1=$(echo "$snetmask"|cut -d. -f1); local netmaskFIELD2=$(echo "$snetmask"|cut -d. -f2); local netmaskFIELD3=$(echo "$snetmask"|cut -d. -f3); local netmaskFIELD4=$(echo "$snetmask"|cut -d. -f4); local tmpret1=$((ipFIELD1&netmaskFIELD1)); local tmpret2=$((ipFIELD2&netmaskFIELD2)); local tmpret3=$((ipFIELD3&netmaskFIELD3)); local tmpret4=$((ipFIELD4&netmaskFIELD4)); echo "$tmpret1.$tmpret2.$tmpret3.$tmpret4"; }; Check_DNS_IP(){ if [ "$1" != "${1#*[0-9].[0-9]}" ];then if [ "$(calc_ip_net "$1" 255.0.0.0)" == "10.0.0.0" ];then echo 0; elif [ "$(calc_ip_net "$1" 255.240.0.0)" == "172.16.0.0" ];then echo 0; elif [ "$(calc_ip_net "$1" 255.255.0.0)" == "169.254.0.0" ];then echo 0; elif [ "$(calc_ip_net "$1" 255.255.0.0)" == "192.168.0.0" ];then echo 0; elif [ "$(calc_ip_net "$1" 255.255.255.0)" == "$(calc_ip_net "$2" 255.255.255.0)" ];then echo 0; else echo 1; fi; elif [ "$1" != "${1#*[0-9a-fA-F]:*}" ];then if [ "${1:0:3}" == "fe8" ];then echo 0; elif [ "${1:0:3}" == "FE8" ];then echo 0; elif [ "${1:0:2}" == "fc" ];then echo 0; elif [ "${1:0:2}" == "FC" ];then echo 0; elif [ "${1:0:2}" == "fd" ];then echo 0; elif [ "${1:0:2}" == "FD" ];then echo 0; elif [ "${1:0:2}" == "ff" ];then echo 0; elif [ "${1:0:2}" == "FF" ];then echo 0; else echo 1; fi; else echo 0; fi; }; Check_DNS_1(){ local resultdns=$(nslookup $1 2>/dev/null); local resultinlines=(${resultdns//$'\n'/ }); local resultindex=0; for i in ${resultinlines[*]};do if [[ $i == "Name:" ]];then local resultdnsindex=$((resultindex+3)); break; fi; resultindex=$((resultindex+1)); done; echo $(Check_DNS_IP ${resultinlines[$resultdnsindex]} ${resultinlines[1]}); }; Check_DNS_2(){ local resultdnstext=$(dig $1 2>/dev/null|grep "ANSWER:"); local resultdnstext=${resultdnstext#*"ANSWER: "}; local resultdnstext=${resultdnstext%", AUTHORITY:"*}; if [ "$resultdnstext" == "0" ]||[ "$resultdnstext" == "1" ]||[ "$resultdnstext" == "2" ];then echo 0; else echo 1; fi; }; Check_DNS_3(){ local resultdnstext=$(dig "test$RANDOM$RANDOM.$1" 2>/dev/null|grep "ANSWER:"); local resultdnstext=${resultdnstext#*"ANSWER: "}; local resultdnstext=${resultdnstext%", AUTHORITY:"*}; if [ "$resultdnstext" == "0" ];then echo 1; else echo 0; fi; }; Get_Unlock_Type_Str(){ local type_str="原生"; while [ $# -ne 0 ];do if [ "$1" = "0" ];then type_str="DNS"; break; fi; shift; done; echo "$type_str"; }

    # --- UA 和 Cookie 辅助函数 ---
    generate_random_user_agent(){
        declare -A browsers=(
            [Chrome]="139.0.7258.128 138.0.7204.102 137.0.7151.122 136.0.7103.116"
            [Firefox]="132.0 131.0 130.0 129.0"
        )
        local browsers_keys=(${!browsers[@]})
        local random_browser_index=$((RANDOM%${#browsers_keys[@]}))
        local browser=${browsers_keys[random_browser_index]}
        case $browser in
        Chrome)local versions=(${browsers[Chrome]})
            local version=${versions[RANDOM%${#versions[@]}]}
            UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/$version Safari/537.36"
        ;;
        Firefox)local versions=(${browsers[Firefox]})
            local version=${versions[RANDOM%${#versions[@]}]}
            UA_Browser="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:$version) Gecko/20100101 Firefox/$version"
        esac
    }
    read_ref(){
        Media_Cookie=$(curl $CurlARG -sL --retry 3 --max-time 10 "${rawgithub}main/ref/cookies.txt")
    }

    # --- 核心检测函数 (已修改为直接打印) ---
    MediaUnlockTest_TikTok(){
        local service_name="TikTok"
        # 移除进度条 local temp_info="$Font_Cyan$Font_B${sinfo[media]}${Font_I}$service_name $Font_Suffix"; ((ibar_step+=3)); show_progress_bar "$temp_info" $((40-7-${sinfo[lmedia]}))& bar_pid="$!"&&disown "$bar_pid"; trap "kill_progress_bar" RETURN
        local checkunlockurl="tiktok.com"
        local result1=$(Check_DNS_1 $checkunlockurl)
        local result3=$(Check_DNS_3 $checkunlockurl)
        local resultunlocktype=$(Get_Unlock_Type_Str $result1 $result3) # 获取 "原生" 或 "DNS"
        local Ftmpresult=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -sL -m 10 "https://www.tiktok.com/")
        if [[ $Ftmpresult == "curl"* ]];then
            red "$service_name: 失败 (Curl Error)"
            return
        fi
        local FRegion=$(echo $Ftmpresult|grep '"region":'|sed 's/.*"region"//'|cut -f2 -d'"')
        if [ -n "$FRegion" ];then
            if [ "$resultunlocktype" == "DNS" ]; then
                yellow "$service_name: 解锁 $resultunlocktype [$FRegion]"
            else
                green "$service_name: 解锁 $resultunlocktype [$FRegion]"
            fi
            return
        fi
        local STmpresult=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -sL -m 10 -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9" -H "Accept-Encoding: gzip" -H "Accept-Language: en" "https://www.tiktok.com"|gunzip 2>/dev/null)
        local SRegion=$(echo $STmpresult|grep '"region":'|sed 's/.*"region"//'|cut -f2 -d'"')
        if [ -n "$SRegion" ];then
             yellow "$service_name: 解锁 机房 [$SRegion]" # 特殊标记机房
            return
        else
            red "$service_name: 失败"
            return
        fi
    }
    MediaUnlockTest_DisneyPlus(){
         local service_name="Disney+"
        # 移除进度条 local temp_info="$Font_Cyan$Font_B${sinfo[media]}${Font_I}$service_name $Font_Suffix"; ((ibar_step+=3)); show_progress_bar "$temp_info" $((40-8-${sinfo[lmedia]}))& bar_pid="$!"&&disown "$bar_pid"; trap "kill_progress_bar" RETURN
        local checkunlockurl="disneyplus.com"
        local result1=$(Check_DNS_1 $checkunlockurl)
        local result3=$(Check_DNS_3 $checkunlockurl)
        local resultunlocktype=$(Get_Unlock_Type_Str $result1 $result3)
        local PreAssertion=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/devices" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -H "content-type: application/json; charset=UTF-8" -d '{"deviceFamily":"browser","applicationRuntime":"chrome","deviceProfile":"windows","attributes":{}}' 2>&1)
        if [[ $PreAssertion == "curl"* ]]; then red "$service_name: 失败 (Curl Error 1)"; return; fi
        if ! (echo "$PreAssertion"|jq . >/dev/null 2>&1); then red "$service_name: 失败 (JSON Error 1)"; return; fi
        
        local assertion=$(echo $PreAssertion|jq -r '.assertion')
        local PreDisneyCookie=$(echo "$Media_Cookie"|sed -n '1p')
        local disneycookie=$(echo $PreDisneyCookie|sed "s/DISNEYASSERTION/$assertion/g")
        local TokenContent=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -s --max-time 10 -X POST "https://disney.api.edge.bamgrid.com/token" -H "authorization: Bearer ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycookie" 2>&1)
        if ! (echo "$TokenContent"|jq . >/dev/null 2>&1); then red "$service_name: 失败 (JSON Error 2)"; return; fi
        
        local isBanned=$(echo $TokenContent|jq -r 'select(.error_description == "forbidden-location") | .error_description')
        local is403=$(echo $TokenContent|grep '403 ERROR')
        if [ -n "$isBanned" ]||[ -n "$is403" ];then red "$service_name: 失败 (Region Block)"; return; fi
        
        local fakecontent=$(echo "$Media_Cookie"|sed -n '8p')
        local refreshToken=$(echo $TokenContent|jq -r '.refresh_token')
        local disneycontent=$(echo $fakecontent|sed "s/ILOVEDISNEY/$refreshToken/g")
        local tmpresult=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -X POST -sSL --max-time 10 "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" -H "authorization: ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84" -d "$disneycontent" 2>&1)
        if ! (echo "$tmpresult"|jq . >/dev/null 2>&1);then red "$service_name: 失败 (JSON Error 3)"; return; fi
        
        local previewcheck=$(curl $CurlARG -$1 -s -o /dev/null -L --max-time 10 -w '%{url_effective}\n' "https://disneyplus.com"|grep preview)
        local isUnavailable=$(echo $previewcheck|grep 'unavailable')
        local region=$(echo $tmpresult|jq -r '.extensions.sdk.session.location.countryCode')
        local inSupportedLocation=$(echo $tmpresult|jq -r '.extensions.sdk.session.inSupportedLocation')

        if [[ $region == "JP" ]]; then
            if [ "$resultunlocktype" == "DNS" ]; then yellow "$service_name: 解锁 $resultunlocktype [JP]"; else green "$service_name: 解锁 $resultunlocktype [JP]"; fi
        elif [ -n "$region" ] && [[ $inSupportedLocation == "false" ]] && [ -z "$isUnavailable" ]; then
            yellow "$service_name: 待支持 [$region]"
        elif [ -n "$region" ] && [ -n "$isUnavailable" ]; then
            red "$service_name: 失败 (Unavailable)"
        elif [ -n "$region" ] && [[ $inSupportedLocation == "true" ]]; then
             if [ "$resultunlocktype" == "DNS" ]; then yellow "$service_name: 解锁 $resultunlocktype [$region]"; else green "$service_name: 解锁 $resultunlocktype [$region]"; fi
        elif [ -z "$region" ]; then
             red "$service_name: 失败 (No Region)"
        else
            red "$service_name: 失败 (Unknown)"
        fi
    }
    MediaUnlockTest_Netflix(){
        local temp_info="$Font_Cyan$Font_B${sinfo[media]}${Font_I}Netflix $Font_Suffix"
        ((ibar_step+=3))
        show_progress_bar "$temp_info" $((40-8-${sinfo[lmedia]}))&
        bar_pid="$!"&&disown "$bar_pid"
        trap "kill_progress_bar" RETURN
        # (修正) 移除 netflix=()
        local checkunlockurl="netflix.com"
        local result1=$(Check_DNS_1 $checkunlockurl)
        local result2=$(Check_DNS_2 $checkunlockurl)
        local result3=$(Check_DNS_3 $checkunlockurl)
        local resultunlocktype=$(Get_Unlock_Type $result1 $result2 $result3)
        local result1=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -fsL -X GET --max-time 10 --tlsv1.3 "https://www.netflix.com/title/81280792" 2>&1)
        local result2=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -fsL -X GET --max-time 10 --tlsv1.3 "https://www.netflix.com/title/70143836" 2>&1)
        if [ -z "$result1" ]||[ -z "$result2" ];then
            netflix[ustatus]="${smedia[bad]}"
            netflix[uregion]="${smedia[nodata]}"
            netflix[utype]="${smedia[nodata]}"
            return
        fi
        local region=$(echo "$result1"|grep -o 'data-country="[A-Z]*"'|sed 's/.*="\([A-Z]*\)"/\1/'|head -n1)
        [[ -z $region ]]&&region=$(echo "$result2"|grep -o 'data-country="[A-Z]*"'|sed 's/.*="\([A-Z]*\)"/\1/'|head -n1)
        result1=$(echo $result1|grep 'Oh no!')
        result2=$(echo $result1|grep 'Oh no!')
        if [ -n "$result1" ]&&[ -n "$result2" ];then
            netflix[ustatus]="${smedia[org]}"
            netflix[uregion]="  [$region]   "
            netflix[utype]="$resultunlocktype"
            return
        fi
        if [ -z "$result1" ]||[ -z "$result2" ];then
            netflix[ustatus]="${smedia[yes]}"
            netflix[uregion]="  [$region]   "
            netflix[utype]="$resultunlocktype"
            return
        fi
        netflix[ustatus]="${smedia[no]}"
        netflix[uregion]="${smedia[nodata]}"
        netflix[utype]="${smedia[nodata]}"
    }
    MediaUnlockTest_Netflix(){
        local service_name="Netflix"
        # 移除进度条 local temp_info="$Font_Cyan$Font_B${sinfo[media]}${Font_I}$service_name $Font_Suffix"; ((ibar_step+=3)); show_progress_bar "$temp_info" $((40-8-${sinfo[lmedia]}))& bar_pid="$!"&&disown "$bar_pid"; trap "kill_progress_bar" RETURN
        local checkunlockurl="netflix.com"
        local result1_dns=$(Check_DNS_1 $checkunlockurl)
        local result2_dns=$(Check_DNS_2 $checkunlockurl)
        local result3_dns=$(Check_DNS_3 $checkunlockurl)
        local resultunlocktype=$(Get_Unlock_Type_Str $result1_dns $result2_dns $result3_dns)
        local result1=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -fsL -X GET --max-time 10 --tlsv1.3 "https://www.netflix.com/title/81280792" 2>&1)
        local result2=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -fsL -X GET --max-time 10 --tlsv1.3 "https://www.netflix.com/title/70143836" 2>&1)
        
        if [ -z "$result1" ] && [ -z "$result2" ]; then # Both curl failed
             red "$service_name: 失败 (Curl Error)"
             return
        fi

        local region=""
        # Try to get region from result1 first, then result2 if result1 failed
        if [ -n "$result1" ]; then
            region=$(echo "$result1"|grep -o 'data-country="[A-Z]*"'|sed 's/.*="\([A-Z]*\)"/\1/'|head -n1)
        fi
         if [ -z "$region" ] && [ -n "$result2" ]; then # If region still empty and result2 succeeded
            region=$(echo "$result2"|grep -o 'data-country="[A-Z]*"'|sed 's/.*="\([A-Z]*\)"/\1/'|head -n1)
        fi

        # Check for "Oh no!" - indicates Originals Only
        local originals_only=0
        if [ -n "$result1" ] && echo "$result1" | grep -q 'Oh no!'; then originals_only=1; fi
        if [ -n "$result2" ] && echo "$result2" | grep -q 'Oh no!'; then originals_only=$((originals_only + 1)); fi # Count how many "Oh no!" we got

        if [ "$originals_only" -eq 2 ]; then # Both titles showed "Oh no!"
            yellow "$service_name: 仅自制 [$region]"
        elif [ "$originals_only" -eq 0 ] && [ -n "$region" ]; then # Neither showed "Oh no!", region found
             if [ "$resultunlocktype" == "DNS" ]; then yellow "$service_name: 解锁 $resultunlocktype [$region]"; else green "$service_name: 解锁 $resultunlocktype [$region]"; fi
        elif [ "$originals_only" -gt 0 ] && [ -n "$region" ]; then # One showed "Oh no!", one didn't - Still consider it unlocked
             if [ "$resultunlocktype" == "DNS" ]; then yellow "$service_name: 解锁 $resultunlocktype [$region]"; else green "$service_name: 解锁 $resultunlocktype [$region]"; fi
        else # No region found or other errors
             red "$service_name: 失败"
        fi
    }
    MediaUnlockTest_YouTube_Premium(){
        local service_name="YouTube"
        # 移除进度条 local temp_info="$Font_Cyan$Font_B${sinfo[media]}${Font_I}$service_name $Font_Suffix"; ((ibar_step+=3)); show_progress_bar "$temp_info" $((40-8-${sinfo[lmedia]}))& bar_pid="$!"&&disown "$bar_pid"; trap "kill_progress_bar" RETURN
        local checkunlockurl="www.youtube.com"
        local result1=$(Check_DNS_1 $checkunlockurl)
        local result3=$(Check_DNS_3 $checkunlockurl)
        local resultunlocktype=$(Get_Unlock_Type_Str $result1 $result3)
        local tmpresult=$(curl $CurlARG -$1 --max-time 10 -sSL -H "Accept-Language: en" "https://www.youtube.com/premium" 2>&1)
        if [[ $tmpresult == "curl"* ]];then red "$service_name: 失败 (Curl Error)"; return; fi
        
        local isCN=$(echo $tmpresult|grep 'www.google.cn')
        if [ -n "$isCN" ];then red "$service_name: 失败 (CN Redirect)"; return; fi
        
        local isNotAvailable=$(echo $tmpresult|grep 'Premium is not available in your country')
        local region=$(echo $tmpresult|sed -n 's/.*"contentRegion":"\([^"]*\)".*/\1/p')
        local isAvailable=$(echo $tmpresult|grep 'ad-free')

        if [ -n "$isNotAvailable" ];then
            yellow "$service_name: 仅免费版可用 [$region]" # Changed "No Premium" to this
        elif [ -n "$isAvailable" ] && [ -n "$region" ];then
             if [ "$resultunlocktype" == "DNS" ]; then yellow "$service_name: 解锁 Premium $resultunlocktype [$region]"; else green "$service_name: 解锁 Premium $resultunlocktype [$region]"; fi
        elif [ -z "$region" ] && [ -n "$isAvailable" ];then # Premium available but no region detected
             if [ "$resultunlocktype" == "DNS" ]; then yellow "$service_name: 解锁 Premium $resultunlocktype [??]"; else green "$service_name: 解锁 Premium $resultunlocktype [??]"; fi
        else
            red "$service_name: 失败 (Unknown)"
        fi
    }
   
MediaUnlockTest_PrimeVideo_Region(){
         local service_name="AmazonPV"
        # 移除进度条 local temp_info="$Font_Cyan$Font_B${sinfo[media]}${Font_I}Amazon $Font_Suffix"; ((ibar_step+=3)); show_progress_bar "$temp_info" $((40-7-${sinfo[lmedia]}))& bar_pid="$!"&&disown "$bar_pid"; trap "kill_progress_bar" RETURN
        local checkunlockurl="www.primevideo.com"
        local result1=$(Check_DNS_1 $checkunlockurl)
        local result3=$(Check_DNS_3 $checkunlockurl)
        local resultunlocktype=$(Get_Unlock_Type_Str $result1 $result3)
        local tmpresult=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -sL --max-time 10 "https://www.primevideo.com" 2>&1)
        if [[ $tmpresult == "curl"* ]];then red "$service_name: 失败 (Curl Error)"; return; fi
        
        local region=$(echo $tmpresult|grep '"currentTerritory":'|sed 's/.*currentTerritory//'|cut -f3 -d'"'|head -n 1)
        if [ -n "$region" ];then
             if [ "$resultunlocktype" == "DNS" ]; then yellow "$service_name: 解锁 $resultunlocktype [$region]"; else green "$service_name: 解锁 $resultunlocktype [$region]"; fi
        else
            red "$service_name: 失败"
        fi
    }
    MediaUnlockTest_Spotify(){
        local service_name="Spotify"
        # 移除进度条 local temp_info="$Font_Cyan$Font_B${sinfo[media]}${Font_I}$service_name $Font_Suffix"; ((ibar_step+=3)); show_progress_bar "$temp_info" $((40-8-${sinfo[lmedia]}))& bar_pid="$!"&&disown "$bar_pid"; trap "kill_progress_bar" RETURN
        local checkunlockurl="spclient.wg.spotify.com" # Using obscured domain
        local result1=$(Check_DNS_1 $checkunlockurl)
        local result3=$(Check_DNS_3 $checkunlockurl)
        local resultunlocktype=$(Get_Unlock_Type_Str $result1 $result3)
        # Using obscured domain in curl call too
        local tmpresult=$(curl $CurlARG -$1 --user-agent "$UA_Browser" -s --max-time 10 -X POST "https://spclient.wg.spotify.com/signup/public/v1/account" -d "birth_day=11&birth_month=11&birth_year=2000&collect_personal_info=undefined&creation_flow=&creation_point=https%3A%2F%2Fwww.spotify.com%2Fhk-en%2F&displayname=Gay%20Lord&gender=male&iagree=1&key=a1e486e2729f46d6bb368d6b2bcda326&platform=www&referrer=&send-email=0&thirdpartyemail=0&identifier_token=AgE6YTvEzkReHNfJpO114514" -H "Accept-Language: en" 2>&1)
        
        if echo "$tmpresult"|jq . >/dev/null 2>&1;then
            local region=$(echo $tmpresult|jq -r '.country')
            local isLaunched=$(echo $tmpresult|jq -r '.is_country_launched')
            local StatusCode=$(echo $tmpresult|jq -r '.status')
            
            if [ "$StatusCode" = "311" ] && [ "$isLaunched" = "true" ]; then
                 if [ "$resultunlocktype" == "DNS" ]; then yellow "$service_name: 解锁 $resultunlocktype [$region]"; else green "$service_name: 解锁 $resultunlocktype [$region]"; fi
            elif [ "$StatusCode" = "320" ] || [ "$StatusCode" = "120" ]; then
                red "$service_name: 失败 (Region Block)"
            else
                red "$service_name: 失败 (API Status $StatusCode)"
            fi
        else
           red "$service_name: 失败 (API Error)"
        fi
    }
    OpenAITest(){
        local service_name="ChatGPT"
        # 移除进度条 local temp_info="$Font_Cyan$Font_B${sinfo[ai]}${Font_I}$service_name $Font_Suffix"; ((ibar_step+=3)); show_progress_bar "$temp_info" $((40-8-${sinfo[lai]}))& bar_pid="$!"&&disown "$bar_pid"; trap "kill_progress_bar" RETURN
        local checkunlockurl1="chat.openai.com"; local checkunlockurl2="ios.chat.openai.com"; local checkunlockurl3="api.openai.com"
        local r1=$(Check_DNS_1 $checkunlockurl1); local r2=$(Check_DNS_2 $checkunlockurl1); local r3=$(Check_DNS_3 $checkunlockurl1)
        local r4=$(Check_DNS_1 $checkunlockurl2); local r5=$(Check_DNS_2 $checkunlockurl2); local r6=$(Check_DNS_3 $checkunlockurl2)
        local r7=$(Check_DNS_1 $checkunlockurl3); local r8=$(Check_DNS_3 $checkunlockurl3)
        local resultunlocktype=$(Get_Unlock_Type_Str $r1 $r2 $r3 $r4 $r5 $r6 $r7 $r8)
        
        # Test API access (platform.openai.com requirement)
        local tmpresult1=$(curl $CurlARG -$1 -sS --max-time 10 'https://api.openai.com/compliance/cookie_requirements' -H 'authority: api.openai.com' -H 'accept: */*' -H 'accept-language: en-US,en;q=0.9' -H 'authorization: Bearer null' -H 'content-type: application/json' -H 'origin: https://platform.openai.com' -H 'referer: https://platform.openai.com/' -H "user-agent: $UA_Browser" 2>&1)
        # Test iOS App access endpoint
        local tmpresult2=$(curl $CurlARG -$1 -sS --max-time 10 'https://ios.chat.openai.com/' -H 'authority: ios.chat.openai.com' -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' -H 'accept-language: en-US,en;q=0.9' -H "user-agent: $UA_Browser" 2>&1)
        
        local api_blocked=$(echo $tmpresult1|grep -q 'unsupported_country' && echo "yes")
        local ios_blocked=$(echo $tmpresult2|grep -q 'VPN' && echo "yes")
        local countryCode=""
        # Faster way to get country code if curl succeeds
        if [[ $tmpresult1 != "curl"* ]]; then
             countryCode="$(curl $CurlARG --max-time 5 -sS https://chat.openai.com/cdn-cgi/trace 2>&1|grep "loc="|awk -F= '{print $2}')"
        elif [[ $tmpresult2 != "curl"* ]]; then # Fallback if API curl failed but iOS didn't
             countryCode="$(curl $CurlARG --max-time 5 -sS https://chat.openai.com/cdn-cgi/trace 2>&1|grep "loc="|awk -F= '{print $2}')"
        fi
         [ -z "$countryCode" ] && countryCode="??" # Default if trace fails

        if [ "$api_blocked" != "yes" ] && [ "$ios_blocked" != "yes" ]; then
             if [ "$resultunlocktype" == "DNS" ]; then yellow "$service_name: 解锁 $resultunlocktype [$countryCode]"; else green "$service_name: 解锁 $resultunlocktype [$countryCode]"; fi
        elif [ "$api_blocked" == "yes" ] && [ "$ios_blocked" == "yes" ]; then
            red "$service_name: 失败"
        elif [ "$api_blocked" != "yes" ] && [ "$ios_blocked" == "yes" ]; then
             yellow "$service_name: 仅网页可用 [$countryCode]"
        elif [ "$api_blocked" == "yes" ] && [ "$ios_blocked" != "yes" ]; then
             yellow "$service_name: 仅 APP 可用 [$countryCode]"
        else # Handle curl errors
             red "$service_name: 失败 (Curl Error)"
        fi
    }
    # --- 函数主执行体 ---
    
    # 获取 IP (使用全局 IP 变量)
    # IP=$(curl -s ipv4.ip.sb || curl -s ifconfig.me) # No longer needed here
    if [ -z "$IP" ]; then
        IP=$(curl -s ipv4.ip.sb || curl -s ifconfig.me) # Try again if global IP is empty
        if [ -z "$IP" ]; then
             red "❌ 自动获取公网 IP 失败"
             read -rp "按任意键返回菜单..."
             return
         fi
    fi
    
    # 初始化
    # ibar_step=0 # Removed progress bar
    # clear # Don't clear here, clear in the main loop

    # 生成 UA 并读取 Cookie
    generate_random_user_agent
    read_ref
    
    # 按顺序执行检测 (全部使用 IPv4)
    # Kill progress bar is removed as progress bar is removed
    MediaUnlockTest_TikTok 4
    MediaUnlockTest_DisneyPlus 4
    MediaUnlockTest_Netflix 4
    MediaUnlockTest_YouTube_Premium 4
    MediaUnlockTest_PrimeVideo_Region 4
    MediaUnlockTest_Spotify 4
    OpenAITest 4
    
    # echo -ne "$Font_LineClear" 1>&2 # Removed progress bar clear

    # 移除 show_media 调用

    echo # Add a blank line for spacing
    green "检测完成。"
    # (修改) 添加感谢
    yellow "感谢xy开源"
    read -rp "按任意键返回菜单..."
}

# 0. 依赖检查 (已修改)
check_deps() {
    # (已修改) 增加了 dnsutils 和 netcat-openbsd
    green "正在检查基础依赖 (curl, wget, jq, xxd, tar, bc, clear, dnsutils, nc)..."
    local missing=0
    local missing_pkgs=""
    
    check_cmd() {
        local cmd=$1
        local pkg=$2
        if ! command -v $cmd &> /dev/null; then
            yellow "未找到 $cmd... (需要 $pkg)"
            missing=1
            # 记录缺失的包，避免重复安装
            if ! echo "$missing_pkgs" | grep -q "$pkg"; then
                missing_pkgs+="$pkg "
            fi
        fi
    }

    check_cmd "curl" "curl"
    check_cmd "wget" "wget"
    check_cmd "jq" "jq"
    check_cmd "xxd" "xxd"
    check_cmd "tar" "tar"
    check_cmd "bc" "bc"
    check_cmd "clear" "ncurses-bin"
    check_cmd "dig" "dnsutils"
    check_cmd "nslookup" "dnsutils"
    check_cmd "nc" "netcat-openbsd"

    if [ "$missing" -eq 1 ]; then
        yellow "正在尝试自动安装缺失的依赖：$missing_pkgs"
        if command -v apt &> /dev/null; then
            apt update -y >/dev/null 2>&1
            apt install -y $missing_pkgs >/dev/null 2>&1
        else
            red "非 apt 系统，请手动安装 $missing_pkgs"
            exit 1
        fi
        
        # 重新检查
        green "重新检查依赖..."
        check_deps
    fi
    green "✅ 依赖检查通过"
}

#====== 主菜单循环 ======
check_deps # 运行一次依赖检查
check_connectivity || true # (新增) 检查网络连接性 (修正：|| true 防止 set -e 退出)
set_language || true # (修正) 同样防止 set -e 退出
adapt_locale || true # (修正) 同样防止 set -e 退出

while true; do
    clear || true
    green "========= Xray 一键安装脚本 ========="
    green "by sddlol website:cloud.cnmsb.cfd (已修改)"
    echo "1. 安装 VLESS + Reality"
    echo "2. 进行测速 (Ookla Speedtest)"
    echo "3. ip质量检测 (感谢xy开源)"
    echo "4. 流媒体解锁检测(感谢xy开源)" 
    echo "5. 退出" 
    echo "====================================="
    read -p "请选择模式 [1-5]: " MODE

    case "$MODE" in
        1)
            install_vless_reality
            ;;
        2)
            run_speedtest
            ;;
        3)
            run_ip_quality_check || true
            ;;
        4)
            run_streaming_check # 你新增的 case
            ;;
        5)
            green "退出脚本。"
            exit 0 # 正常退出
            ;;
        *)
            red "无效输入，请输入 1-5 之间的数字。"
            sleep 2 # 暂停2秒让用户看到错误
            ;;
    esac
done