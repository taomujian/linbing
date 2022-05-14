#!/usr/bin/env python3

import re
import sys
import time
import asyncio
import hashlib
from bs4 import BeautifulSoup as BS
from app.lib.common import get_useragent
from app.lib.request import request

class Fofa_Scanner:
    def __init__(self, target, fofa_finger_list):
        self.target = target
        self.fofa_finger_list = fofa_finger_list
        self.start = time.time()
        self.finger = []
        self.rtitle = re.compile(r'title="(.*)"')
        self.rheader = re.compile(r'header="(.*)"')
        self.rbody = re.compile(r'body="(.*)"')
        self.rbracket = re.compile(r'\((.*)\)')
        self.cms_finger_list = [
            '08cms', '1039_jxt', '1039\xe5\xae\xb6\xe6\xa0\xa1\xe9\x80\x9a', '3gmeeting', '3gmeeting\xe8\xa7\x86\xe8\xae\xaf\xe7\xb3\xbb\xe7\xbb\x9f', '51fax\xe4\xbc\xa0\xe7\x9c\x9f\xe7\xb3\xbb\xe7\xbb\x9f', '53kf', '5ucms', '686_weixin', '6kbbs', '74cms', '86cms', 'afterlogicwebmail\xe7\xb3\xbb\xe7\xbb\x9f', 'appcms', 'aspcms', 'b2bbuilder', 'beescms', 'bookingecms\xe9\x85\x92\xe5\xba\x97\xe7\xb3\xbb\xe7\xbb\x9f', 'cactiez\xe6\x8f\x92\xe4\xbb\xb6', 'chinacreator', 'cxcms', 'dk\xe5\x8a\xa8\xe7\xa7\x91cms', 'doyo\xe9\x80\x9a\xe7\x94\xa8\xe5\xbb\xba\xe7\xab\x99\xe7\xb3\xbb\xe7\xbb\x9f', 'dtcms', 'dvrdvs-webs', 'datalifeengine', 'dayucms', 'dedecms', 'destoon', 'digital campus2.0', 'digitalcampus2.0', 'discuz', 'discuz7.2', 'drupal', 'dswjcms', 'duomicms', 'dvbbs', 'dzzoffice', 'ecshop', 'ec_word\xe4\xbc\x81\xe4\xb8\x9a\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', 'emlog', 'easysite\xe5\x86\x85\xe5\xae\xb9\xe7\xae\xa1\xe7\x90\x86', 'edusoho', 'empirecms', 'epaper\xe6\x8a\xa5\xe5\x88\x8a\xe7\xb3\xbb\xe7\xbb\x9f', 'epoint', 'espcms', 'fengcms', 'foosuncms', 'gentlecms', 'gever', 'glassfish', 'h5\xe9\x85\x92\xe5\xba\x97\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', 'hdwiki', 'hjcms\xe4\xbc\x81\xe4\xb8\x9a\xe7\xbd\x91\xe7\xab\x99\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', 'himail', 'hishop\xe5\x95\x86\xe5\x9f\x8e\xe7\xb3\xbb\xe7\xbb\x9f', 'hituxcms', 'ilas\xe5\x9b\xbe\xe4\xb9\xa6\xe7\xb3\xbb\xe7\xbb\x9f', 'iloanp2p\xe5\x80\x9f\xe8\xb4\xb7\xe7\xb3\xbb\xe7\xbb\x9f', 'imo\xe4\xba\x91\xe5\x8a\x9e\xe5\x85\xac\xe5\xae\xa4\xe7\xb3\xbb\xe7\xbb\x9f', 'insightsoft', 'iwebshop', 'iwmscms', 'jboos', 'jishigou', 'jeecms', 'jingyi', 'joomla', 'kangle\xe8\x99\x9a\xe6\x8b\x9f\xe4\xb8\xbb\xe6\x9c\xba', 'kesioncms', 'kessioncms', 'kingcms', 'lebishop\xe7\xbd\x91\xe4\xb8\x8a\xe5\x95\x86\xe5\x9f\x8e', 'live800', 'live800\xe6\x8f\x92\xe4\xbb\xb6', 'ljcms', 'mlecms', 'mailgard', 'majexpress', 'mallbuilder', 'maticsoftsns', 'minyoocms', 'mvmmall', 'mymps\xe8\x9a\x82\xe8\x9a\x81\xe5\x88\x86\xe7\xb1\xbb\xe4\xbf\xa1\xe6\x81\xaf', 'n\xe7\x82\xb9\xe8\x99\x9a\xe6\x8b\x9f\xe4\xb8\xbb\xe6\x9c\xba', 'opensns', 'ourphp', 'php168', 'phpcms', 'phpwind', 'phpok', 'piw\xe5\x86\x85\xe5\xae\xb9\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', 'phpmyadmin', 'phpwind\xe7\xbd\x91\xe7\xab\x99\xe7\xa8\x8b\xe5\xba\x8f', 'pigcms', 'powercreator\xe5\x9c\xa8\xe7\xba\xbf\xe6\x95\x99\xe5\xad\xa6\xe7\xb3\xbb\xe7\xbb\x9f', 'powereasy', 'sapnetweaver', 'shopex', 'shop7z', 'shopnc\xe5\x95\x86\xe5\x9f\x8e\xe7\xb3\xbb\xe7\xbb\x9f', 'shopnum', 'siteserver', 'soullon', 'southidc', 'supesite', 't-site\xe5\xbb\xba\xe7\xab\x99\xe7\xb3\xbb\xe7\xbb\x9f', 'theol\xe7\xbd\x91\xe7\xbb\x9c\xe6\x95\x99\xe5\xad\xa6\xe7\xbb\xbc\xe5\x90\x88\xe5\xb9\xb3\xe5\x8f\xb0', 'trs\xe8\xba\xab\xe4\xbb\xbd\xe8\xae\xa4\xe8\xaf\x81\xe7\xb3\xbb\xe7\xbb\x9f', 'tipask\xe9\x97\xae\xe7\xad\x94\xe7\xb3\xbb\xe7\xbb\x9f', 'tomcat', 'trsids', 'trunkey', 'turbomail\xe9\x82\xae\xe7\xae\xb1\xe7\xb3\xbb\xe7\xbb\x9f', 'v2\xe8\xa7\x86\xe9\xa2\x91\xe4\xbc\x9a\xe8\xae\xae\xe7\xb3\xbb\xe7\xbb\x9f', 'v5shop', 'venshop2010\xe5\x87\xa1\xe4\xba\xba\xe7\xbd\x91\xe7\xbb\x9c\xe8\xb4\xad\xe7\x89\xa9\xe7\xb3\xbb\xe7\xbb\x9f', 'vos3000', 'veryide', 'wcm\xe7\xb3\xbb\xe7\xbb\x9fv6', 'wordpress', 'ws2004\xe6\xa0\xa1\xe5\x9b\xad\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', 'wangzt', 'weblogic', 'webmail', 'weboffice', 'webnet cms', 'webnetcms', 'wilmaroa\xe7\xb3\xbb\xe7\xbb\x9f', 'winmail server', 'winmailserver', 'wizbank', 'xplus\xe6\x8a\xa5\xe7\xa4\xbe\xe7\xb3\xbb\xe7\xbb\x9f', 'xpshop', 'yidacms', 'yongyou', 'z-blog', 'zabbix', 'zoomla', 'abcms', 'able_g2s', 'acsno', 'acsoft', 'actcms', 'adtsec_gateway', 'akcms', 'anleye', 'anmai', 'anmai\xe5\xae\x89\xe8\x84\x89\xe6\x95\x99\xe5\x8a\xa1\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', 'anymacromail', 'apabi_tasi', 'asiastar_sm', 'aten_kvm', 'atripower', 'avcon6', 'axis2', 'ayacms', 'b2cgroup', 'baiaozhi', 'beidou', 'bluecms', 'boblog', 'bocweb', 'bohoog', 'bytevalue_router', 'canon', 'chamilo-lms', 'ckfinder', 'cmseasy', 'cmstop', 'cnoa', 'codeigniter', 'comexe_ras', 'cscms', 'cutecms', 'd-link', 'dahua_dss', 'daiqile_p2p', 'dalianqianhao', 'damall', 'damicms', 'dfe_scada', 'dianyips', 'diguocms\xe5\xb8\x9d\xe5\x9b\xbd', 'dircms', 'dkcms', 'dossm', 'douphp', 'dreamgallery', 'dubbo', 'eshangbao\xe6\x98\x93\xe5\x95\x86\xe5\xae\x9d', 'easethink', 'easy7\xe8\xa7\x86\xe9\xa2\x91\xe7\x9b\x91\xe6\x8e\xa7\xe5\xb9\xb3\xe5\x8f\xb0', 'ecweb_shop', 'edayshop', 'edjoy', 'eduplate', 'edusohocms', 'eims', 'eimscms', 'electric_monitor', 'empire_cms', 'enableq', 'enjie_soft', 'es-cloud', 'esafenet_dlp', 'esccms', 'ewebs', 'expocms', 'extmail', 'eyou', 'e\xe5\x88\x9b\xe7\xab\x99', 'fang5173', 'fangwei', 'fastmeeting', 'fcms', 'fcms\xe6\xa2\xa6\xe6\x83\xb3\xe5\xbb\xba\xe7\xab\x99', 'feifeicms', 'feiyuxing_router', 'finecms', 'fiyocms', 'foosun', 'foosun\xe6\x96\x87\xe7\xab\xa0\xe7\xb3\xbb\xe7\xbb\x9f', 'fsmcms', 'gbcom_wlan', 'genixcms', 'gnuboard', 'gocdkey', 'gooine_sqjz', 'gowinsoft_jw', 'gxcms', 'hac_gateway', 'haitianoa', 'hanweb', 'haohan', 'heeroa', 'hf_firewall', 'hongzhi', 'horde_email', 'house5', 'hsort', 'huachuang_router', 'huanet', 'huashi_tv', 'humhub', 'idvr', 'ipowercms', 'iceflow_vpn_router', 'ideacms', 'ieadcms', 'iflytek_soft', 'igenus', 'ikuai', 'insight', 'jenkins', 'jienuohan', 'jieqicms', 'jindun_gateway', 'jingci_printer', 'jinpan', 'jinqiangui_p2p', 'jishitongxun', 'joomle', 'jumbotcms', 'juniper_vpn', 'kill_firewall', 'kingdee_eas', 'kingdee_oa', 'kinggate', 'kingosoft_xsweb', 'kj65n_monitor', 'klemanndesign', 'kuwebs', 'kxmail', 'landray', 'lebishop', 'lezhixing_datacenter', 'lianbangsoft', 'liangjing', 'libsys', 'linksys', 'looyu_live', 'ltpower', 'luepacific', 'luzhucms', 'lvmaque', 'maccms', 'magento', 'mailgard-webmail', 'mainone_b2b', 'maopoa', 'maxcms', 'mbbcms', 'metinfo', 'mikrotik_router', 'moxa_nport_router', 'mpsec', 'myweb', 'nanjing_shiyou', 'natshell', 'nbcms', 'net110', 'netcore', 'netgather', 'netoray_nsg', 'netpower', 'newvane_onlineexam', 'nitc', 'nitc\xe5\xae\x9a\xe6\xb5\xb7\xe7\xa5\x9e\xe7\x9c\x9f', 'niubicms', 'ns-asg', 'otcms', 'pageadmin', 'panabit', 'phpb2b', 'phpcmsv9', 'phpdisk', 'phpmaps', 'phpmps', 'phpmywind', 'phpshe', 'phpshop', 'phpvibe', 'phpweb', 'phpwiki', 'phpyun', 'piaoyou', 'pkpmbs', 'plc_router', 'powercreator', 'qht_study', 'qianbocms', 'qibosoft', 'qiuxue', 'qizhitong_manager', 'qzdatasoft\xe5\xbc\xba\xe6\x99\xba\xe6\x95\x99\xe5\x8a\xa1\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', 'rockoa', 'rockontrol', 'ruijie_router', 'ruvar_oa', 'ruvarhrm', 's8000', 'santang', 'sdcms', 'seagate_nas', 'seawind', 'seentech_uccenter', 'sgc8000', 'shadows-it', 'shenlan_jiandu', 'shlcms', 'shopnum1', 'shopxp', 'shuangyang_oa', 'siteengine', 'sitefactory', 'skypost', 'skytech', 'smart_oa', 'soffice', 'soullon_edu', 'srun_gateway', 'star-net', 'startbbs', 'strongsoft', 'subeicms', 'syncthru_web_service', 'synjones_school', 'syxxjs', 'sztaiji_zw', 'taocms', 'taodi', 'terramaster', 'thinkox', 'thinkphp', 'thinksns', 'tianbo_train', 'tianrui_lib', 'tipask', 'tongdaoa', 'topsec', 'totalsoft_lib', 'tp-link', 'trs_ids', 'trs_inforadar', 'trs_lunwen', 'trs_wcm', 'typecho', 'umail', 'uniflows', 'unis_gateway', 'uniwin_gov', 'urp', 'v2_conference', 'vbulletin', 'vicworl', 'visionsoft_velcro', 'wangqushop', 'wdcp', 'wdscms', 'weaver_oa', 'websitebaker', 'wecenter', 'weixinpl', 'weway_soft', 'wisedu_elcs', 'workyisystem', 'workyi_system', 'wygxcms', 'xdcms', 'xiaowuyou_cms', 'xikecms', 'xinhaisoft', 'xinyang', 'xinzuobiao', 'xplus', 'xr_gatewayplatform', 'xuezi_ceping', 'xycms', 'ynedut_campus', 'yongyou_a8', 'yongyou_crm', 'yongyou_ehr', 'yongyou_fe', 'yongyou_icc', 'yongyou_nc', 'yongyou_u8', 'yongyou_zhiyuan_a6', 'yuanwei_gateway', 'yxlink', 'zblog', 'zcncms', 'zdsoft_cnet', 'zentao', 'zeroboard', 'zf_cms', 'zfsoft', 'zhongdongli_school', 'zhonghaida_vnet', 'zhongqidonglicms', 'zhongruan_firewall', 'zhoupu', 'zhuangxiu', 'zhuhaigaoling_huanjingzaosheng', 'zmcms', 'zmcms\xe5\xbb\xba\xe7\xab\x99', 'zte', 'zuitu', 'zzcms', '\xe4\xb8\x87\xe4\xbc\x97\xe7\x94\xb5\xe5\xad\x90\xe6\x9c\x9f\xe5\x88\x8acms', '\xe4\xb8\x87\xe5\x8d\x9a\xe7\xbd\x91\xe7\xab\x99\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f2006', '\xe4\xb8\x87\xe5\x8d\x9a\xe7\xbd\x91\xe7\xab\x99\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe4\xb8\x87\xe6\x88\xb7oa', '\xe4\xb8\x87\xe6\xac\xa3\xe9\xab\x98\xe6\xa0\xa1\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe4\xb8\x89\xe6\x89\x8d\xe6\x9c\x9f\xe5\x88\x8a\xe7\xb3\xbb\xe7\xbb\x9f', '\xe4\xb8\xad\xe4\xbc\x81\xe5\x8a\xa8\xe5\x8a\x9bcms', '\xe4\xb9\x90\xe5\xbd\xbc\xe5\xa4\x9a\xe7\xbd\x91\xe5\xba\x97', '\xe4\xba\xbf\xe9\x82\xaeemail', '\xe4\xbc\x81\xe6\x99\xba\xe9\x80\x9a\xe7\xb3\xbb\xe5\x88\x97\xe4\xb8\x8a\xe7\xbd\x91\xe8\xa1\x8c\xe4\xb8\xba\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe4\xbc\x97\xe6\x8b\x93', '\xe5\x85\xa8\xe7\xa8\x8boa', '\xe5\x87\xa1\xe8\xaf\xba\xe4\xbc\x81\xe4\xb8\x9a\xe7\xbd\x91\xe7\xab\x99\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\x88\x86\xe7\xb1\xbb\xe4\xbf\xa1\xe6\x81\xaf\xe7\xbd\x91bank.asp\xe5\x90\x8e\xe9\x97\xa8', '\xe5\x88\x9b\xe6\x8d\xb7\xe9\xa9\xbe\xe6\xa0\xa1\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\x8d\x8e\xe5\xa4\x8f\xe5\x88\x9b\xe6\x96\xb0appex\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\x8d\x97\xe6\x96\xb9\xe6\x95\xb0\xe6\x8d\xae', '\xe5\x8f\xa3\xe7\xa6\x8f\xe7\xa7\x91\xe6\x8a\x80', '\xe5\x91\xb3\xe5\xa4\x9a\xe7\xbe\x8e\xe5\xaf\xbc\xe8\x88\xaa', '\xe5\x95\x86\xe5\xa5\x87cms', '\xe5\x95\x86\xe5\xae\xb6\xe4\xbf\xa1\xe6\x81\xaf\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\x9b\x9b\xe9\x80\x9a\xe6\x94\xbf\xe5\xba\x9c\xe7\xbd\x91\xe7\xab\x99\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\xa4\xa7\xe6\xb1\x89jcms', '\xe5\xa4\xa9\xe6\x9f\x8f\xe5\x9c\xa8\xe7\xba\xbf\xe8\x80\x83\xe8\xaf\x95\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\xa4\xa9\xe8\x9e\x8d\xe4\xbf\xa1panabit', '\xe5\xae\x81\xe5\xbf\x97\xe5\xad\xa6\xe6\xa0\xa1\xe7\xbd\x91\xe7\xab\x99', '\xe5\xae\x81\xe5\xbf\x97\xe5\xad\xa6\xe6\xa0\xa1\xe7\xbd\x91\xe7\xab\x99\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\xae\x89\xe4\xb9\x90\xe4\xb8\x9a\xe6\x88\xbf\xe4\xba\xa7\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\xae\x9a\xe6\xb5\xb7\xe7\xa5\x9e\xe7\x9c\x9f', '\xe5\xb0\x8f\xe8\xae\xa1\xe5\xa4\xa9\xe7\xa9\xba\xe8\xbf\x9b\xe9\x94\x80\xe5\xad\x98\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\xb0\x98\xe6\x9c\x88\xe4\xbc\x81\xe4\xb8\x9a\xe7\xbd\x91\xe7\xab\x99\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\xb0\x98\xe7\xbc\x98\xe9\x9b\x85\xe5\xa2\x83\xe5\x9b\xbe\xe6\x96\x87\xe7\xb3\xbb\xe7\xbb\x9f', '\xe5\xbb\xba\xe7\xab\x99\xe4\xb9\x8b\xe6\x98\x9f', '\xe5\xbe\xae\xe6\x93\x8e\xe7\xa7\x91\xe6\x8a\x80', '\xe6\x82\x9f\xe7\xa9\xbacrm', '\xe6\x82\x9f\xe7\xa9\xbacrm\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x93\x8e\xe5\xa4\xa9\xe6\x94\xbf\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x96\xb0\xe4\xb8\xba\xe8\xbd\xaf\xe4\xbb\xb6e-learning\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x96\xb0\xe7\xa7\x80', '\xe6\x96\xb9\xe7\xbb\xb4\xe5\x9b\xa2\xe8\xb4\xad', '\xe6\x96\xb9\xe7\xbb\xb4\xe5\x9b\xa2\xe8\xb4\xad\xe8\xb4\xad\xe7\x89\xa9\xe5\x88\x86\xe4\xba\xab\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x97\xb6\xe4\xbb\xa3\xe4\xbc\x81\xe4\xb8\x9a\xe9\x82\xae', '\xe6\x98\x8e\xe8\x85\xbecms', '\xe6\x98\x93\xe5\x88\x9b\xe6\x80\x9d', '\xe6\x98\x93\xe5\x88\x9b\xe6\x80\x9d\xe6\x95\x99\xe8\x82\xb2\xe5\xbb\xba\xe7\xab\x99\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x98\x93\xe6\x83\xb3cms', '\xe6\x99\xba\xe7\x9d\xbf\xe7\xbd\x91\xe7\xab\x99\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x9c\x80\xe5\x9c\x9f\xe5\x9b\xa2\xe8\xb4\xad\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x9c\xaa\xe7\x9f\xa5oem\xe5\xae\x89\xe9\x98\xb2\xe7\x9b\x91\xe6\x8e\xa7\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x9c\xaa\xe7\x9f\xa5\xe6\x94\xbf\xe5\xba\x9c\xe9\x87\x87\xe8\xb4\xad\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x9c\xaa\xe7\x9f\xa5\xe6\x9f\xa5\xe8\xaf\xa2\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\x9d\xad\xe5\xb7\x9e\xe5\x8d\x9a\xe9\x87\x87cms', '\xe6\x9d\xb0\xe5\xa5\x87\xe5\xb0\x8f\xe8\xaf\xb4\xe8\xbf\x9e\xe8\xbd\xbd\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\xa1\x83\xe6\xba\x90\xe7\x9b\xb8\xe5\x86\x8c\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\xb1\x87\xe6\x88\x90\xe4\xbc\x81\xe4\xb8\x9a\xe5\xbb\xba\xe7\xab\x99cms', '\xe6\xb1\x87\xe6\x96\x87\xe5\x9b\xbe\xe4\xb9\xa6\xe9\xa6\x86\xe4\xb9\xa6\xe7\x9b\xae\xe6\xa3\x80\xe7\xb4\xa2\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\xb1\x89\xe7\xa0\x81\xe9\xab\x98\xe6\xa0\xa1\xe6\xaf\x95\xe4\xb8\x9a\xe7\x94\x9f\xe5\xb0\xb1\xe4\xb8\x9a\xe4\xbf\xa1\xe6\x81\xaf\xe7\xb3\xbb\xe7\xbb\x9f', '\xe6\xb3\x9b\xe5\xbe\xaee-office', '\xe6\xb3\x9b\xe5\xbe\xaeoa', '\xe6\xb5\xaa\xe6\xbd\xaecms', '\xe6\xb5\xb7\xe5\xba\xb7\xe5\xa8\x81\xe8\xa7\x86', '\xe7\x88\xb1\xe6\xb7\x98\xe5\xae\xa2', '\xe7\x88\xb1\xe8\xa3\x85\xe7\xbd\x91', '\xe7\x94\xa8\xe5\x8f\x8bfe\xe5\x8d\x8f\xe4\xbd\x9c\xe5\x8a\x9e\xe5\x85\xac\xe5\xb9\xb3\xe5\x8f\xb0', '\xe7\x94\xa8\xe5\x8f\x8bfe\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe7\x94\xa8\xe5\x8f\x8bturbcrm\xe7\xb3\xbb\xe7\xbb\x9f', '\xe7\x94\xa8\xe5\x8f\x8bu8', '\xe7\x94\xa8\xe5\x8f\x8b', '\xe7\x9a\x93\xe7\xbf\xb0\xe9\x80\x9a\xe7\x94\xa8\xe6\x95\xb0\xe5\xad\x97\xe5\x8c\x96\xe6\xa0\xa1\xe5\x9b\xad\xe5\xb9\xb3\xe5\x8f\xb0', '\xe7\x9c\x81\xe7\xba\xa7\xe5\x86\x9c\xe6\x9c\xba\xe6\x9e\x84\xe7\xbd\xae\xe8\xa1\xa5\xe8\xb4\xb4\xe4\xbf\xa1\xe6\x81\xaf\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe7\xa7\x91\xe4\xbf\xa1\xe9\x82\xae\xe4\xbb\xb6\xe7\xb3\xbb\xe7\xbb\x9f', '\xe7\xa7\x91\xe8\xbf\x88ras', '\xe7\xa8\x8b\xe6\xb0\x8f\xe8\x88\x9e\xe6\x9b\xb2cms', '\xe7\xbb\xbf\xe9\xba\xbb\xe9\x9b\x80\xe5\x80\x9f\xe8\xb4\xb7\xe7\xb3\xbb\xe7\xbb\x9f', '\xe7\xbd\x91\xe8\xb6\xa3\xe5\x95\x86\xe5\x9f\x8e', '\xe7\xbd\x91\xe9\x92\x9b\xe6\x96\x87\xe7\xab\xa0\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe8\x80\x81y\xe6\x96\x87\xe7\xab\xa0\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe8\x81\x94\xe4\xbc\x97mediinfo\xe5\x8c\xbb\xe9\x99\xa2\xe7\xbb\xbc\xe5\x90\x88\xe7\xae\xa1\xe7\x90\x86\xe5\xb9\xb3\xe5\x8f\xb0', '\xe8\x87\xaa\xe5\x8a\xa8\xe5\x8f\x91\xe5\x8d\xa1\xe5\xb9\xb3\xe5\x8f\xb0', '\xe8\x89\xaf\xe7\xb2\xbe\xe5\x8d\x97\xe6\x96\xb9', '\xe8\x89\xba\xe5\xb8\x86cms', '\xe8\x8f\xb2\xe6\x96\xaf\xe7\x89\xb9\xe8\xaf\xba\xe6\x9c\x9f\xe5\x88\x8a\xe7\xb3\xbb\xe7\xbb\x9f', '\xe8\x93\x9d\xe5\x87\x8ceis\xe6\x99\xba\xe6\x85\xa7\xe5\x8d\x8f\xe5\x90\x8c\xe5\xb9\xb3\xe5\x8f\xb0', '\xe8\x93\x9d\xe7\xa7\x91cms', '\xe8\x96\x84\xe5\x86\xb0\xe6\x97\xb6\xe6\x9c\x9f\xe7\xbd\x91\xe7\xab\x99\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe8\xae\xaf\xe6\x97\xb6\xe7\xbd\x91\xe7\xab\x99\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9fcms', '\xe8\xae\xb0\xe4\xba\x8b\xe7\x8b\x97', '\xe8\xb4\xb7\xe9\xbd\x90\xe4\xb9\x90\xe7\xb3\xbb\xe7\xbb\x9f', '\xe9\x80\x9a\xe8\xbe\xbeoa\xe7\xb3\xbb\xe7\xbb\x9f', '\xe9\x80\x9f\xe8\xb4\x9dcms', '\xe9\x87\x91\xe8\x89\xb2\xe6\xa0\xa1\xe5\x9b\xad', '\xe9\x87\x91\xe8\x9d\xb6oa', '\xe9\x87\x91\xe8\x9d\xb6\xe5\x8d\x8f\xe4\xbd\x9c\xe5\x8a\x9e\xe5\x85\xac\xe7\xb3\xbb\xe7\xbb\x9f', '\xe9\x87\x91\xe9\x92\xb1\xe6\x9f\x9cp2p', '\xe9\x9b\x86\xe6\x97\xb6\xe9\x80\x9a\xe8\xae\xaf\xe7\xa8\x8b\xe5\xba\x8f', '\xe9\x9c\xb2\xe7\x8f\xa0\xe6\x96\x87\xe7\xab\xa0\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe9\x9d\x92\xe4\xba\x91\xe5\xae\xa2cms', '\xe9\x9d\x92\xe5\xb3\xb0\xe7\xbd\x91\xe7\xbb\x9c\xe6\x99\xba\xe8\x83\xbd\xe7\xbd\x91\xe7\xab\x99\xe7\xae\xa1\xe7\x90\x86\xe7\xb3\xbb\xe7\xbb\x9f', '\xe9\x9d\x92\xe6\x9e\x9c\xe5\xad\xa6\xe7\x94\x9f\xe7\xb3\xbb\xe7\xbb\x9f', '\xe9\x9d\x92\xe6\x9e\x9c\xe5\xad\xa6\xe7\x94\x9f\xe7\xbb\xbc\xe5\x90\x88\xe7\xb3\xbb\xe7\xbb\x9f', '\xe9\x9d\x92\xe6\x9e\x9c\xe6\x95\x99\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f', '\xe9\x9d\x92\xe6\x9e\x9c\xe8\xbd\xaf\xe4\xbb\xb6\xe6\x95\x99\xe5\x8a\xa1\xe7\xb3\xbb\xe7\xbb\x9f', '\xe9\x9d\x9e\xe5\x87\xa1\xe5\xbb\xba\xe7\xab\x99'
        ]

    async def get_info(self):

        """
        获取网站的headers、网页内容和标题信息的原始内容

        :param:

        :return tuple headers, content, title: 获取到的原始信息
        """

        try:
            UA = get_useragent()
            headers = {
                'User-Agent': UA
            }
            req = await request.get(url = self.target, headers = headers, verify = False)
            content = await req.text()
            headers_str = ''
            try:
                title = BS(content, 'lxml').title.text.strip()
                for key, value in req.headers.items():
                    headers_str = headers_str + key + ': ' + value + ','
                return headers_str, content, title.strip('\n')
            except:
                for key, value in req.headers.items():
                    headers_str = headers_str + key + ': ' + value + ','
                return headers_str, content, ''
        except Exception as e:
            # print(e)
            return '', '', ''
        finally:
            pass

    def check_rule(self, key, header, body, title):

        """
        根据原始的内容来提取headers、 content, title

        :param:

        :return bool: 是否获取到了信息
        """

        try:
            if 'title="' in key:
                if re.findall(self.rtitle, key)[0].lower() in title.lower():
                    return True
            elif 'body="' in key:
                if re.findall(self.rbody, key)[0] in body: return True
            else:
                if re.findall(self.rheader, key)[0] in header: return True
        except Exception as e:
            # print(e)
            pass
        finally:
            pass

    async def handle(self, header, body, title, key, name):

        """
        取出指纹库的key进行匹配
        
        :param _id: 指纹的id
        :param header: 原始的header信息
        :param body: 原始的body信息
        :param title: 原始的title信息
        :param key: fofa指纹
        :param name: fofa指纹名字

        :return:
        
        """
        
        try:
            # 满足一个条件即可的情况
            if '||' in key and '&&' not in key and '(' not in key:
                for rule in key.split('||'):
                    if self.check_rule(rule, header, body, title):
                        self.finger.append(name)
                        
                        break
            # 只有一个条件的情况
            elif '||' not in key and '&&' not in key and '(' not in key:
                if self.check_rule(key, header, body, title):
                    self.finger.append(name)
                    
            # 需要同时满足条件的情况
            elif '&&' in key and '||' not in key and '(' not in key:
                num = 0
                for rule in key.split('&&'):
                    if self.check_rule(rule, header, body, title):
                        num += 1
                if num == len(key.split('&&')):
                    self.finger.append(name)
                    
            else:
                # 与条件下存在并条件: 1||2||(3&&4)
                if '&&' in re.findall(self.rbracket, key)[0]:
                    for rule in key.split('||'):
                        if '&&' in rule:
                            num = 0
                            for _rule in rule.split('&&'):
                                if self.check_rule(_rule, header, body, title):
                                    num += 1
                            if num == len(rule.split('&&')):
                                self.finger.append(name)
                                
                                break
                        else:
                            if self.check_rule(rule, header, body, title):
                                self.finger.append(name)
                                
                                break
                else:
                    # 并条件下存在与条件： 1&&2&&(3||4)
                    for rule in key.split('&&'):
                        num = 0
                        if '||' in rule:
                            for _rule in rule.split('||'):
                                if self.check_rule(_rule, title, body, header):
                                    num += 1
                                    break
                        else:
                            if self.check_rule(rule, title, body, header):
                                num += 1
                    if num == len(key.split('&&')):
                        self.finger.append(name)
        except:
            pass

    async def run(self):
        
        """
        程序入口

        :param: 

        :return:
        """
        
        header, body, title = await self.get_info()
        for item in self.fofa_finger_list:
            key = item['key_str']
            name = item['fofa_cms_type']
            await self.handle(header, body, title, key, name)

        return self.finger

class WhatCms:
    def __init__(self, target, cms):
        self.cms = cms
        self.diction = {}
        self.target = target
        self.info = []

    def getMD5(self, content):

        """
        获取文件的请求头

        :param str or bytes content: 要进行的哈希的content

        :return str hash_str: 文件内容的MD5值
        """

        if isinstance(content,str):
            content = content.encode()
        m = hashlib.md5()
        m.update(content)
        hash_str = m.hexdigest()
        return hash_str

    async def request_url(self, url):

        """
        获取url的内容

        :param str url: 请求的url

        :return tuple req.text, req.content: url的内容和url内容的原始编码
        """

        

        try:
            UA = get_useragent()
            headers = {
                'User-Agent': UA
            }
            req = await request.get(url = url, headers = headers)
            if req.status == 200:
                response_text = await req.text()
                response_content = await req.read()
                return response_text, response_content
            else:
                return '',''
        except Exception as e:
            # print(e)
            return '', ''

    async def coroutine_execution(self, semaphore, url, cms_name, match_pattern, options):

        """
        多协程执行方法

        :param str func: 待执行方法
        :param loop loop: loop 对象
        :param int semaphore: 协程并发数量
        :param str url: 请求的url
        :param str finger_id: 指纹id号
        :param str cms_name: cms名字
        :param str path: 指纹的path
        :param str match_pattern: 要匹配的字符串
        :param str options: 指纹匹配类型
        
        :return:
        """

        async with semaphore:
            try:
                response_html, response_content = await self.request_url(url)
                if response_html and response_content:
                    if options == 'md5':
                        if match_pattern == self.getMD5(response_content):
                            self.info.append(cms_name + '\n')
                    elif options == 'keyword':
                        if match_pattern.lower() in response_html.lower():
                            self.info.append(cms_name + '\n')

                    elif options == 'regx':
                        r = re.search(match_pattern, response_html)
                        if r:
                            self.info.append(cms_name + '\n')

            except Exception as e:
                # print(e)
                pass

    async def find_powered_by(self):

        """
        根据powered by关键字获取cms类型

        :param: 
        :return bool True, False: 是否找到了关键字
        """
        
        text, content = await self.request_url(self.target)
        match = re.search('Powered by (.*)', text, re.I)
        if match:
            clear_html_cms = re.sub('<.*?>', '', match.group(1))
            cms_name = clear_html_cms.split(' ')[0]
            if cms_name:
                self.info.append(cms_name + '\n')

    async def find_cms_with_file(self):

        """
        根据数据库的指纹来判断网站类型

        :param:
        
        :return:
        """
        
        semaphore = asyncio.Semaphore(int('1000'))
        tasks = []
        for eachline in self.cms:
            cms_name, path, match_pattern, options = eachline['cms_type'], eachline['path'], eachline['match_pattern'], eachline['options']
            url = self.target + path
            task = asyncio.create_task(self.coroutine_execution(semaphore, url, cms_name, match_pattern, options))
            tasks.append(task)

        await asyncio.gather(*tasks)

    async def run(self):

        """
        程序入口

        :param: 

        :return:
        """
    
        await self.find_cms_with_file()
        await self.find_powered_by()
        return self.info

if __name__ == "__main__":
    target_url = sys.argv[1]

    # mysqldb = Mysql_db('192.168.202.128', '3306', 'root', '123456')
    #　finger_list = mysqldb.all_finger('admin')
    # cms = Fofa_Scanner(target_url, finger_list['fofa_cms'])
    cms = Fofa_Scanner(target_url, '')
    fofa_finger = cms.run()
    fofa_banner = ''
    cms_name = ''
    cms_name_flag = 0
    for fofa_finger_tmp in fofa_finger:
        fofa_banner= fofa_banner + ' '+fofa_finger_tmp
        if fofa_finger_tmp.lower() in cms.cms_finger_list:
            cms_name = fofa_finger_tmp
            cms_name_flag = 1
            print(cms_name, 1223)

    if not cms_name_flag:
        # whatcms = WhatCms(target_url, finger_list['cms'])
        whatcms = WhatCms(target_url, '')
        result = whatcms.run()
        print(result)
        cms_name = ''
        if result:
            print("CMS__finger:", result)