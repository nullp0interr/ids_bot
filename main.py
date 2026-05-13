import os
import asyncio
import re
import asyncpg
from dotenv import load_dotenv
from datetime import datetime
from pyrogram import Client, filters
from excel_reporter import generate_ansible_report
load_dotenv()

# Секреты
API_ID = int(os.getenv("API_ID", 0))
API_HASH = os.getenv("API_HASH")
ALERT_CHAT_ID = int(os.getenv("ALERT_CHAT_ID", 0))
DATABASE_URL = os.getenv("DATABASE_URL")

# ЧАТЫ
listen_raw = os.getenv("LISTEN_CHATS", "")
LISTEN_CHATS = [int(i.strip()) for i in listen_raw.split(",") if i.strip()]
TARGET_CHATS = [ALERT_CHAT_ID]

# СПИСКИ
ALLOWED_IPS = os.getenv("ALLOWED_IPS", "").split(",")
ALLOWED_USERS = os.getenv("ALLOWED_USERS", "").split(",")
IGNORE_BAD_IP_CLIENTS = os.getenv("IGNORE_BAD_IP_CLIENTS", "").split(",")
CPANEL_SKIP_IPS = os.getenv("CPANEL_SKIP_IPS", "").split(",")
ATAK_SKIP_IPS = os.getenv("ATAK_SKIP_IPS", "").split(",")

WATCH_LIST = {
    ("itc", "Kronex_evrosklad-new"): "контроль доступа itc на Kronex_evrosklad-new",
    ("zruchna", "VetMedia-PBX-Sys"): "контроль доступа ZRUCHNA на VetMedia-PBX-Sys",
    ("itcenter", "Nemokna-new-ats"): "контроль доступа itcenter на Nemokna-new-ats",
    ("itcenter", "Confidens"): "контроль доступа itcenter на Confidens",
    ("itcenter_sergeym", "Sonodin-new"): "контроль доступа itcenter_sergeym на Sonodin-new",
    ("zruchna", "PBX-Ulc-LXC"): "контроль доступа zruchna на PBX-Ulc-LXC",
    ("itcenter", "pbx-bydom-lxc"): "контроль доступа itcenter на pbx-bydom-lxc",
    ("zruchna", "PBX-DPM_New-VM-mtscloud"): "контроль доступа zruchna на PBX-DPM_New-VM-mtscloud"
}

ANSIBLE_TEST_LIST = {
    "7Video-NewCloud": "10.5.3.44",
    "100kotlov-NewSys": "172.17.85.124",
    "500-amper-new": "192.168.1.71",
    "A13-PBX": "172.16.71.14",
    "AGS-PBX-SYS": "172.17.85.180",
    "AI-CloudBOT": "10.100.85.235",
    "akkymby": "172.16.55.183",
    "akvilon-new-new": "82.209.216.107",
    "Alfa-ressail": "172.16.55.205",
    "Aliviatarget-Proxi-Becloud": "172.16.71.252",
    "Amigo-gsm": "172.16.71.249",
    "ankron-ats": "172.16.55.194",
    "Ankron-gsm2": "172.16.70.79",
    "Anuta-Dent-GSM": "172.16.55.118",
    "Armstrong": "172.16.55.174",
    "Armstrong-gsm-1": "172.16.71.231",
    "Armstrong-Proxi-BeCloud": "172.16.71.242",
    "Asmantatelecom": "172.16.70.3",
    "ASTERISK-TRUNK-LXC": "10.4.5.73",
    "AstikonSnab-VM": "172.17.85.61",
    "ATS-calltracking": "192.168.25.52",
    "AutoDrug-92": "172.17.85.2",
    "AvtoImperialMotors": "172.16.71.135",
    "Avtosona": "192.168.209.1",
    "Balhim": "172.16.70.1",
    "BamService-VM": "172.17.85.118",
    "Baranovichi-express": "10.5.3.3",
    "BelAgroVetFarm-Sys": "172.17.85.108",
    "Belakvamir-asterisk": "86.57.244.146",
    "BelAuditAlliance": "172.17.85.96",
    "BelAvtoSpecGroup-PBX-VM": "172.16.71.163",
    "Belavtotrade": "192.168.211.1",
    "Belfresh": "172.16.55.212",
    "BelinfoCenter-Cloud": "172.16.71.73",
    "Belsansist": "172.16.55.173",
    "BelSemTorgPlus-SYS": "172.17.85.101",
    "Belsklad": "172.16.70.74",
    "Belsmartorange": "172.16.70.29",
    "Beltransputink-PBX2": "172.16.71.10",
    "Beltransputnik-asterisk": "172.16.70.5",
    "Belux": "172.16.55.26",
    "benzograd": "172.16.55.188",
    "Bibicar-Sys": "172.16.71.164",
    "Bina": "172.16.71.144",
    "Bina-Proxi-MTS": "172.16.71.211",
    "BK_Tesla-VM": "172.16.71.132",
    "Borigran": "172.16.55.93",
    "BS-MS.by-PBX": "172.16.71.68",
    "Buisness-tools-gsm": "172.16.71.43",
    "Buisness-tools-PBX-Cloud": "10.4.5.47",
    "Bydoors": "172.16.55.66",
    "Bysvet-new": "172.16.71.48",
    "CDEK-Minsk_ats": "10.5.3.6",
    "Clinica-ZZ-gsm": "172.16.55.37",
    "Clinica-ZZ-VM": "172.17.85.100",
    "Confidens": "172.16.71.85",
    "Crazyservice": "172.16.70.12",
    "Ctt-ats": "172.16.70.44",
    "Cultivator": "172.16.55.208",
    "darirozy": "172.16.55.3",
    "Datahata-PBX": "172.16.71.37",
    "Datch-Star-VM": "172.16.71.158",
    "Davinagaz-gsm": "172.16.55.231",
    "Davinagaz-new": "172.16.55.95",
    "Dipper-SYS": "172.17.85.30",
    "Dobramaska": "172.16.55.243",
    "Dobryj-vzglyad": "172.16.71.168",
    "Doctor-Set": "172.16.70.63",
    "Domax": "172.16.55.218",
    "Dostavka24-VM": "172.16.71.229",
    "DR-tut": "172.16.55.31",
    "DR-tut-gsm": "172.16.55.32",
    "DVS-Gomel": "172.16.70.8",
    "DVS-Grodno": "172.16.70.58",
    "DVS-Sec": "172.16.70.9",
    "Dvs-Vitebsk": "172.16.70.36",
    "Dzen-Drive-PBX-LXC": "10.4.5.56",
    "Ecotravel": "10.5.3.5",
    "Ecotravel-gsm": "172.16.71.233",
    "Embassy": "172.16.70.42",
    "Evrolombard-SYS": "172.17.85.119",
    "f-med-vm-mts": "172.16.71.88",
    "Fabrika-Mamka-MSK": "172.17.85.5",
    "FaraonTrade": "172.17.85.131",
    "Fclinic": "172.16.70.121",
    "Flario-Call-Center-SYS": "172.16.71.170",
    "ForestMed-PBX-SYS": "172.16.71.154",
    "Furniland-SYS": "172.17.85.51",
    "Garfield-PBX": "172.16.70.80",
    "General-Plast-LXC": "10.4.5.63",
    "Germestrast-okko": "172.17.85.55",
    "Gira-SYS": "172.17.85.83",
    "GKSouz-LXC": "10.4.5.61",
    "GKSouzMTSBiCloud": "172.16.71.221",
    "Goodroof-ats-rf": "192.168.76.246",
    "GoodSoft": "172.16.70.49",
    "Gos-stroy-expert": "172.16.55.47",
    "grafskaya-gsm": "172.16.55.107",
    "GSM-DzenDrive-OR": "172.16.71.136",
    "GSM-DzenFood-OR-replace": "172.16.71.228",
    "HammerSmith": "172.16.71.106",
    "Heatone-new": "172.16.71.86",
    "Hors": "10.111.0.128",
    "Houze": "172.16.55.199",
    "IkonMarket-SYS": "172.17.85.77",
    "Inho-BecloudVM": "172.17.85.112",
    "innovaclinic-becloud": "172.16.71.226",
    "InOkna": "172.16.55.44",
    "Intalia": "172.16.70.102",
    "Inxo-Bel-Bet": "192.168.212.1",
    "Ionby": "172.16.70.25",
    "IP-Bybnovich-gsm-orange": "172.16.70.110",
    "IP-Bybnovich-LXC": "10.4.5.246",
    "ip-makarchyk-gsm": "172.16.71.74",
    "IP-Makarchyk-PBX-LXC": "10.4.5.13",
    "IpMakarchuk-FerstRFATS": "172.17.85.137",
    "it-guide-pbx-lxc": "10.4.5.20",
    "Janchai-GSM": "172.16.71.5",
    "K5": "172.16.55.172",
    "Kapibara": "172.16.70.94",
    "Kapibara-Baranovichi-lxc": "10.4.5.245",
    "Kapibara-Polostk-LXC": "10.4.5.19",
    "Karzone-orange": "172.16.71.71",
    "Kazany-SYS-GSM": "172.16.71.130",
    "Kazanyby-PBX-Cloud": "10.4.5.241",
    "Kidskey-Cloud": "172.16.71.39",
    "KidsKey-gsm": "172.16.71.102",
    "Klakson": "172.16.55.73",
    "Klimat24": "10.5.3.28",
    "Kordis-VM": "172.16.70.95",
    "Kronex_evrosklad-new": "172.16.70.108",
    "Kryshnya": "172.17.85.82",
    "KurareMedecine-Sys": "172.16.71.128",
    "Ladgorna-SYS": "172.17.85.66",
    "Letride": "172.16.55.109",
    "Lkon-sys": "172.17.85.27",
    "Loft-PBX-Container": "10.4.5.46",
    "Ltop": "172.16.55.120",
    "luukby-new": "172.16.55.13",
    "M1-PBX-LXC": "10.4.5.24",
    "M8-city-VM": "172.16.71.50",
    "Magkompozite": "10.4.5.16",
    "Manager-new": "192.168.25.99",
    "MarketPrice-Sys": "172.16.71.56",
    "Maunfeld-VM": "172.16.71.193",
    "Mavis-PBX-LXC": "10.4.5.29",
    "Mediluks-new": "172.17.85.35",
    "Medprostor": "10.5.3.10",
    "medprostor-gsm": "172.16.70.90",
    "Mejarol-Sys": "172.17.85.64",
    "MindiBy-Vm": "172.17.85.88",
    "Mir-espresso-rezerv": "172.16.55.166",
    "Molodechnosto": "172.16.55.159",
    "Morozoff-ats": "172.16.71.159",
    "Morozoff-ats-maxifone": "192.168.0.62",
    "Morozoff-gsm": "172.16.55.225",
    "Moztehur-gsm": "172.16.55.96",
    "Mozyr-gsm": "172.16.55.146",
    "MusicLand-New": "172.16.71.78",
    "Muzforte-GSM": "172.16.71.153",
    "Mvelo": "172.16.70.52",
    "Myclinic": "172.16.55.38",
    "Nashi-group": "172.16.55.234",
    "Nasosov-New": "172.16.71.237",
    "NDT-ATS": "172.16.70.81",
    "Nemokna-new-ats": "172.16.70.45",
    "NRG-Orha-PBX-VM": "172.16.71.66",
    "Oem-PBX-sys": "172.16.71.30",
    "Olimp-Media": "172.16.55.50",
    "Ostium-Doors-PBX": "172.16.71.238",
    "Otlichnye-lydi": "172.16.70.19",
    "Padarunki-PBX-LXC": "10.4.5.58",
    "Paracels-ATS-HyperV": "172.16.71.150",
    "Parfumeriaby-GSM": "172.16.71.38",
    "PBX-11labs-VM": "172.17.85.123",
    "PBX-AgroNKA-LXC": "10.4.5.42",
    "PBX-AironKomfort-Office-VM": "172.16.71.174",
    "PBX-AjronKomfort-Domofoniya-VM": "172.16.71.129",
    "PBX-Alisveta-SYS": "172.17.85.174",
    "pbx-alivitarget-lxc": "10.4.5.17",
    "PBX-AlsTraiding-SYS": "172.16.71.44",
    "pbx-Amigo-lxc": "10.4.5.158",
    "PBX-Amiko-SYS": "172.17.85.129",
    "pbx-androidfmcdev-lxc": "10.4.5.164",
    "PBX-AnitaBy-SYS": "172.17.85.219",
    "PBX-Antarion-VM": "172.17.85.144",
    "PBX-AnutaDent-VM": "172.17.85.54",
    "pbx-arhstroiconsalt-lxc": "10.4.5.139",
    "PBX-Armis-VM": "172.17.85.193",
    "PBX-AsiaTradeRF-Cloud": "172.17.85.221",
    "pbx-astrapro-lxc": "10.4.5.219",
    "PBX-Asystent_Service-SYS": "172.17.85.197",
    "PBX-AutoStrong-RB-VM": "172.17.85.214",
    "PBX-AutoStrong-RF-VM": "172.17.85.215",
    "PBX-BabyBoss-SYS": "172.17.85.147",
    "pbx-banzai-lxc": "10.4.5.221",
    "PBX-BelarusTorg-SYS": "172.17.85.38",
    "PBX-BelKuhni-SYS": "172.17.85.184",
    "PBX-Belmotors-SYS": "172.17.85.201",
    "PBX-Bemotors-FerstRF": "172.17.85.227",
    "PBX-Blk7-SYS": "172.17.85.124",
    "PBX-Block-modul-rx-zadarma": "84.252.74.113",
    "pbx-bnkestate-lxc": "10.4.5.112",
    "PBX-boboli-LXC-FMC": "10.4.5.75",
    "pbx-bydom-lxc": "10.4.5.116",
    "PBX-Cezar-KZ-Cloud": "172.17.85.75",
    "PBX-Chao-LXC": "10.4.5.15",
    "pbx-checkpbx-lxc": "10.4.5.143",
    "pbx-cityclinic-lxc": "10.4.5.169",
    "PBX-CloudNet-VM": "5.133.123.102",
    "PBX-ComplexMedia-Cloud": "172.17.85.203",
    "PBX-D-Prodact-VM": "172.17.85.46",
    "pbx-dekuver-lxc": "10.4.5.220",
    "PBX-Deltasport-LXC": "10.4.5.67",
    "pbx-democlients-lxc": "10.4.5.153",
    "PBX-Dobryj-vzglyad-VM-Hoster": "172.16.71.80",
    "PBX-DPM_New-VM-mtscloud": "172.17.85.110",
    "pbx-drmotors-lxc": "10.4.5.95",
    "pbx-dzenfood-lxc": "10.4.5.154",
    "PBX-EasySmile-SYS": "172.17.85.136",
    "PBX-EkoRan-VM": "172.16.71.217",
    "PBX-Electocars-VM": "172.16.71.83",
    "PBX-ElefantPlus-SYS": "172.17.85.228",
    "PBX-Emalya-MTS-Cloud": "192.168.216.1",
    "PBX-euroholl-LXC": "10.4.5.55",
    "PBX-Eurotransportservice-MTS": "192.168.214.1",
    "PBX-Eviners-SYS": "172.17.85.170",
    "PBX-Fabrika-Sun-VM": "172.17.85.190",
    "pbx-flario-lxc": "10.4.5.109",
    "PBX-FlarioRF-Cloud": "172.17.85.207",
    "pbx-fmcdemo-lxc": "10.4.5.107",
    "PBX-fmed-VM": "10.4.5.52",
    "pbx-formatelafmc-lxc": "10.4.5.92",
    "PBX-ForPro-VM-RB": "172.17.85.156",
    "PBX-Fraime-SYS": "172.16.71.187",
    "pbx-fun-sun-lxc": "10.4.5.146",
    "PBX-Gals-VM": "172.17.85.149",
    "PBX-garant-nedvizhimost-VM": "172.16.71.224",
    "PBX-Garmonia-SYS": "172.17.85.121",
    "PBX-Genez-LXC": "10.4.5.2",
    "PBX-Grafskaya-SYS": "172.16.71.148",
    "PBX-GrandSkrim-SYS": "172.17.85.168",
    "PBX-GreenTerra-Sys": "172.17.85.211",
    "PBX-Gud_Motors-AgroX-SYS": "172.17.85.217",
    "PBX-Guzal-LXC": "10.4.5.31",
    "PBX-Hobot-SYS": "172.17.85.60",
    "PBX-Hvilina-SYS": "172.17.85.25",
    "PBX-InfokusMedia-SYS": "172.17.85.204",
    "pbx-innovaclinic-lxc": "10.4.5.119",
    "PBX-InsaitMedika-SYS": "172.17.85.142",
    "PBX-InstrumentGroup-SYS": "172.16.71.173",
    "PBX-IP-Makarchuk-SYS": "172.17.85.230",
    "PBX-Irtaka-SYS": "172.17.85.209",
    "PBX-Irvis-SYS": "172.17.85.20",
    "pbx-janchai-lxc": "10.4.5.136",
    "pbx-karkasExpert-lxc": "10.4.5.155",
    "PBX-Kingstyle-VM": "172.17.85.28",
    "PBX-Kravt-SYS": "172.17.85.151",
    "PBX-KVK-VM": "172.17.85.97",
    "PBX-LaerGroup-Cloud": "172.17.85.212",
    "PBX-Lavita-SYS": "172.16.71.84",
    "PBX-LebusGroup-VM": "172.17.85.176",
    "PBX-LegusGroup-VM": "172.17.85.176",
    "PBX-LGService-MINSK-SYS": "172.17.85.225",
    "PBX-Liber21-Cloud": "172.17.85.189",
    "PBX-Linecom-VM": "172.16.71.145",
    "PBX-Luk-KZ-VM": "172.16.71.107",
    "PBX-M-agro-VM": "172.16.71.223",
    "PBX-M8-ZEON": "178.124.209.30",
    "PBX-Malberriklab-VM": "172.17.85.152",
    "pbx-manager-lxc": "10.4.5.101",
    "PBX-MariaMed-SYS": "172.16.71.203",
    "PBX-MarketData-Sys": "172.17.85.196",
    "pbx-maunfeld-lxc": "10.4.5.113",
    "PBX-Med-Diagnoz-SYS": "172.17.85.50",
    "PBX-Mediola-SYS": "172.17.85.65",
    "PBX-Megamoll-VM": "172.17.85.111",
    "pbx-Meko-lxc": "10.4.5.157",
    "PBX-Merida-VM": "172.17.85.187",
    "PBX-MirRemney-SYS": "172.17.85.45",
    "pbx-modernboitech-lxc": "10.4.5.126",
    "PBX-ModulDom-SYS": "172.17.85.154",
    "pbx-moduledev-lxc": "10.4.5.124",
    "pbx-moksi-lxc": "10.4.5.91",
    "PBX-MolotMotors-LXC": "10.4.5.236",
    "pbx-Momo": "10.4.5.148",
    "PBX-MuraveiBy-SYS": "172.17.85.167",
    "PBX-Musliland-SYS": "172.17.85.165",
    "pbx-muzforte-lxc": "10.4.5.121",
    "PBX-NeFox-VM": "172.16.71.202",
    "pbx-neocarsfmc-lxc": "10.4.5.125",
    "PBX-New-lekar-VM": "172.16.71.110",
    "PBX-NMShop-new-sys": "172.17.85.162",
    "PBX-Okonnyi-trest-VM": "172.16.71.178",
    "PBX-Ollari-LXC": "10.4.5.99",
    "PBX-Optik-SYS": "172.16.55.133",
    "PBX-Optisale-SYS": "172.17.85.192",
    "PBX-otlichnye-ludi-LXC": "10.4.5.133",
    "PBX-Parfumeriaby-lxc": "10.4.5.44",
    "PBX-PrivatnyjLekar-SYS": "172.17.85.146",
    "PBX-Procaise-LXC": "10.4.5.6",
    "PBX-Prokat-Petrovich-LXC": "10.4.5.135",
    "PBX-Promira-VM": "172.17.85.127",
    "PBX-Promsfera-VM": "172.17.85.159",
    "pbx-ProRazvitie-lxc": "10.4.5.22",
    "PBX-ProVEDAdvans-VM": "172.17.85.69",
    "PBX-ProvertRF-Cloud": "172.17.85.44",
    "PBX-PulCen-Actual-SYS": "172.17.85.223",
    "PBX-Pulscen-VM": "172.16.71.97",
    "PBX-QCC-VM": "172.17.85.47",
    "PBX-rclinic-sys": "172.17.85.86",
    "pbx-remcompresS-lxc": "10.4.5.117",
    "pbx-rez-nedvij-lxc": "10.4.5.89",
    "PBX-Rich-Kargo-VM": "172.17.85.181",
    "pbx-Rimbat-lxc": "10.4.5.160",
    "PBX-Romis-Sys": "172.16.71.184",
    "PBX-RoyalCRM-VM": "172.17.85.161",
    "PBX-Saga-LXC": "10.4.5.26",
    "PBX-SahalinProject-SYS": "172.17.85.163",
    "PBX-SaleUp-LXC": "10.4.5.10",
    "PBX-SantehForum-SYS": "172.17.85.169",
    "PBX-SantehForum-VM-RF": "147.78.67.210",
    "PBX-SantradeService-VM": "172.16.71.205",
    "PBX-SelectProfit-VM": "172.17.85.194",
    "PBX-Selmax-VM": "172.17.85.164",
    "PBX-SferaCecurity-SYS": "172.17.85.185",
    "PBX-Shagal-LXC": "10.4.5.132",
    "PBX-Shagovita-VM": "172.16.71.209",
    "PBX-Shagovita-VM-RF": "172.17.85.10",
    "PBX-SMmTurbo-LXC": "10.4.5.33",
    "pbx-snab-stroi-service-lxc": "10.4.5.74",
    "pbx-softgarant-lxc": "10.4.5.234",
    "PBX-SplatService-VM": "172.16.71.180",
    "PBX-StarTelecom74-VM": "172.17.85.6",
    "PBX-Stom-Egor-Ruzov-LXC": "10.4.5.5",
    "PBX-System-analitics-SYS": "172.17.85.172",
    "PBX-TehnoGrad-Plus-VM": "172.17.85.195",
    "PBX-TehnoGrad-VM": "172.17.85.155",
    "PBX-Tengen-RF-VM": "172.16.71.204",
    "PBX-Teplodvor-SYS": "172.17.85.183",
    "pbx-testats-lxc": "10.4.5.235",
    "pbx-testzabbix-lxc": "10.4.5.226",
    "PBX-Tiamo-VM": "172.17.85.140",
    "PBX-Triomed_Izumrud-SYS": "172.17.85.171",
    "pbx-tyregby-lxc": "10.4.5.147",
    "PBX-UCOM-LXC": "10.4.5.9",
    "PBX-Ulc-LXC": "10.4.5.130",
    "PBX-Unistar-VM": "172.17.85.105",
    "PBX-Uplast-RF-VM": "172.17.85.106",
    "PBX-Uyutnayamebeldlyadoma-BeCloud": "172.17.85.143",
    "PBX-Vabra-SYS": "172.17.85.42",
    "PBX-VekturaSLK-CloudFB": "172.17.85.148",
    "PBX-Veza-SYS": "172.17.85.145",
    "PBX-Vezaliy-SYS": "172.17.85.191",
    "PBX-Vikowest-SYS": "172.17.85.89",
    "PBX-Viraj_Orsha-SYS": "172.17.85.188",
    "PBX-vk-trans-VM": "172.16.71.191",
    "PBX-Welldoris-LXC": "10.4.5.49",
    "PBX-Westa-VM": "172.17.85.39",
    "PBX-WestMedService-SYS": "172.17.85.62",
    "PBX-Wzap-SYS": "172.17.85.72",
    "PBX-Xistore-Cloud": "172.17.85.222",
    "PBX-Zaborochie-Cloud": "172.17.85.186",
    "PBX-ZoomTeh-LXC": "10.4.5.129",
    "PBX-ZooVet-SYS": "172.16.71.126",
    "PBX-Zubnaya-symfony-SYS": "172.17.85.49",
    "Petrovich-Minsk": "172.16.70.14",
    "Picadilly": "172.16.55.23",
    "Planeta-tepla": "172.16.71.70",
    "Pnevmoteh-new": "172.16.71.40",
    "pokupai-gsm-by": "172.16.55.246",
    "Polivetklinika": "172.16.70.20",
    "PoolBy": "172.16.71.116",
    "PPH.by-asterisk": "10.5.3.12",
    "pphby-gsm": "172.16.70.51",
    "Procaise-gsm-Or": "172.16.71.134",
    "Profimed": "172.16.71.20",
    "ProfLab_Diagnostiks_VM": "172.16.71.151",
    "Promair": "172.16.55.162",
    "Promair-new-VM": "172.16.71.58",
    "Protoks": "172.16.70.32",
    "Proud-Clinic": "172.16.70.50",
    "PROXI-Antarion-BeCloud": "172.17.85.139",
    "PROXI-ForPro-Cloud": "172.17.85.157",
    "Proxi-MTS-Evrolombard": "172.17.85.206",
    "Proxi-Tiamo-BeCloud": "172.17.85.115",
    "ProxiMTS-Irtaka-BeCloud": "172.17.85.213",
    "PTO": "172.16.55.130",
    "Raketa-new": "172.16.70.39",
    "Ravira": "172.16.71.111",
    "Remmers": "172.16.70.40",
    "Resurs-gsm-1": "172.16.70.82",
    "Resurs-new": "172.16.55.124",
    "Retorsia-VM": "172.17.85.70",
    "RodolitAkva-PBX": "172.16.71.19",
    "Saido-VM-RF": "172.17.85.81",
    "Sertificat-ATS": "172.16.71.165",
    "Shedo-VM": "172.17.85.125",
    "Shtutgard-PBX-Cloud": "172.16.71.21",
    "Smartshome": "172.16.55.89",
    "Snab-sys": "172.16.71.147",
    "Soft-Teh-Torg-sys": "172.16.71.79",
    "SoftGarantService-VM": "172.17.85.132",
    "Solmarket-Orange-PBX": "172.16.70.112",
    "Sonodin-new": "172.16.71.82",
    "Specevrotools": "172.16.55.167",
    "spotolok": "172.16.55.11",
    "ST-Med": "192.168.213.1",
    "Staltmk": "172.16.70.70",
    "stom-shabanovicha": "172.17.85.71",
    "stom-triomed-klub": "172.16.55.21",
    "SunFler-SYS": "172.17.85.87",
    "Superbus-PBX-VM": "172.16.71.46",
    "SV-motors-new": "172.16.71.62",
    "Svetofor-sys": "172.16.71.143",
    "Tech_avtoservice": "172.16.55.169",
    "Teh-klining-project": "172.16.71.2",
    "TehnoBeton-NewVm": "172.17.85.134",
    "TerminalData": "172.16.70.103",
    "Termotek": "172.16.55.121",
    "Terol_plast": "172.16.55.75",
    "Tipography": "172.16.70.31",
    "TK375-Asterisk-New-VM": "10.7.12.254",
    "Toursolution": "172.16.55.108",
    "TPkonsalt": "172.16.55.91",
    "Travelhouse": "172.16.55.131",
    "TVS-engineering": "172.16.70.109",
    "Tyreg-GSM": "172.16.71.220",
    "UdilenHolod-VM": "172.16.71.186",
    "Umelye_ruki": "172.16.55.163",
    "Unetby-PBX": "172.16.71.9",
    "Unitel": "172.16.71.235",
    "VashiKlienty-VM": "10.5.3.20",
    "Vay-rb": "172.16.55.17",
    "VetMedia-PBX-Sys": "172.16.71.42",
    "Viraj-Orsha": "172.16.70.115",
    "Viraj-Vitebsk-Sys": "172.17.85.79",
    "Visetehnik-PBX-VM-Hyper-V": "172.16.71.96",
    "Vishop": "172.16.55.112",
    "Vita-MTS": "172.17.85.113",
    "Vita-new-ats": "86.57.182.231",
    "Vitebsk-avto-sity-mts-cloud": "192.168.215.1",
    "Vivaremteh-PBX-SYS": "172.16.71.167",
    "Vlap-avto": "10.0.0.201",
    "VMKDent-VM": "172.16.71.93",
    "Voltra-new": "172.16.70.98",
    "Weichai-PBX": "172.16.70.62",
    "Weldoris-gsm": "172.16.71.166",
    "Westpack": "172.16.55.180",
    "Whitelotus": "10.5.3.7",
    "Whitelotus-gsm": "172.16.70.55",
    "Widget-new": "10.4.5.250",
    "Winstyle": "172.16.55.110",
    "Wise-Engineering": "172.17.85.122",
    "Wolfgroup": "172.16.55.57",
    "zako": "172.16.55.29",
    "Zavod-teplic-mts": "192.168.0.96",
    "Zavod-teplic_old": "192.168.0.100",
    "Zeon-new": "172.16.70.101",
    "Zip24-gsm": "172.16.55.238",
    "Zoologistika-gsm": "172.16.71.89",
    "Zoologistika-PBX": "172.16.71.16",
    "Zruchna-Ansible-VM": "10.100.85.230",
    "Teplica-ats": "172.16.55.90",
    "Kianol-Suhidom": "192.168.203.1"
}


db_pool = None
failed_attempts = {} 
pending_checks = {}  
pending_attacks = {}
last_success_time = {} # время последнего успешного входа по IP

ansible_test_active = False
ansible_test_results = {}

app = Client("my_account", api_id=API_ID, api_hash=API_HASH)

async def init_db():
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL)
    async with db_pool.acquire() as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY, reason TEXT, message_text TEXT, client_ip TEXT, timestamp TIMESTAMP DEFAULT NOW()
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY, client_ip TEXT UNIQUE, reason TEXT, timestamp TIMESTAMP DEFAULT NOW()
            )
        ''')

async def save_alert(reason, message_text, client_ip):
    async with db_pool.acquire() as conn:
        await conn.execute("INSERT INTO alerts (reason, message_text, client_ip) VALUES ($1, $2, $3)", reason, message_text, client_ip)

async def register_incident(client_ip, reason):
    async with db_pool.acquire() as conn:
        await conn.execute("INSERT INTO incidents (client_ip, reason) VALUES ($1, $2) ON CONFLICT DO NOTHING", client_ip, reason)

def parse_ssh_message(text):
    is_success = "SSH-авторизация" in text
    user_match = re.search(r"👤 Пользователь:\s*(.+)", text)
    ip_match = re.search(r"🌍 Клиент:\s*(.+)", text)
    server_ip_match = re.search(r"🖥 Сервер:\s*(.+)", text)
    method_match = re.search(r"🔑 Метод:\s*(.+)", text)
    zabbix_match = re.search(r"📊 Zabbix:\s*(.+)", text)
    return {
        "is_success": is_success,
        "user": user_match.group(1).strip() if user_match else None,
        "ip": ip_match.group(1).strip() if ip_match else None,
        "server_ip": server_ip_match.group(1).strip() if server_ip_match else None,
        "method_is_key": "ключ" in method_match.group(1).lower() if method_match else False,
        "zabbix_name": zabbix_match.group(1).strip() if zabbix_match else None
    }

def is_working_hours():
    now = datetime.now()
    if 7 <= now.hour < 21:
        if now.hour == 7 and now.minute < 30: return False
        return True
    return False

# Таймер для обычного SSH
async def wait_for_success(client, client_ip, original_message):
    await asyncio.sleep(60)
    reason = "[Инцидент]: нет успешной авторизации за 60 секунд после ошибки"
    
    await save_alert(reason, original_message.text, client_ip)
    await register_incident(client_ip, reason)
    
    for chat in TARGET_CHATS:
        try: 
            await client.send_message(chat, f"***{reason}***")
            await original_message.copy(chat)
        except Exception as e: print(f"[!] Ошибка копирования в {chat}: {e}", flush=True)
    print(f"[ALLERT] {reason} | IP: {client_ip}", flush=True)
    
# Таймер для WATCH_LIST
async def wait_for_watchlist_success(client, client_ip, original_message, control_text):
    await asyncio.sleep(60)
    reason = f"КОНТРОЛЬ ДОСТУПА: {control_text} [НЕТ УСПЕШНОГО ВХОДА ЗА 60 СЕК]"
    await save_alert(reason, original_message.text, client_ip)
    await register_incident(client_ip, reason)
    for chat in TARGET_CHATS:
        try:
            await client.send_message(chat, f"***{reason}***")
            await original_message.copy(chat)
        except Exception as e: print(f"[!] Ошибка в {chat}: {e}", flush=True)
    print(f"[ALLERT] {reason} | IP: {client_ip}", flush=True)

# Таймер для АТАК
async def wait_for_atak_resolution(client, src_ip, original_message):
    await asyncio.sleep(60)
    reason = f"[Инцидент]: Зафиксирована активность с IP: {src_ip} (нет подтверждения DST за 60 сек)"
    await save_alert(reason, original_message.text, src_ip)
    await register_incident(src_ip, reason)
    for chat in TARGET_CHATS:
        try: 
            await client.send_message(chat, f"***{reason}***")
            await original_message.copy(chat)
        except Exception as e: print(f"[!] Ошибка алерта атаки в {chat}: {e}", flush=True)
    print(f"[ALLERT] {reason} | IP: {src_ip}", flush=True)

# ================= КОМАНДЫ =================

@app.on_message(filters.command(["status", "ping"]))
async def check_bot_status(client, message):
    if message.chat.id in TARGET_CHATS or message.chat.id in LISTEN_CHATS:
        uptime_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        await message.reply_text(
            f"[ СТАТУС: БОТ АКТИВЕН ]\n"
            f"Время на сервере: {uptime_time}\n"
            f"Слушаю чатов: {len(LISTEN_CHATS)}\n"
            f"Шлю алерты в чатов: {len(TARGET_CHATS)}\n"
            f"Мониторинг логов активен"
        )

@app.on_message(filters.command("test_start"))
async def start_ansible_test(client, message):
    global ansible_test_active, ansible_test_results
    if message.chat.id in TARGET_CHATS or message.chat.id in LISTEN_CHATS:
        ansible_test_active = True
        ansible_test_results = {k: "NO" for k in ANSIBLE_TEST_LIST.keys()}
        await message.reply_text(f"**тестирование запущено**\nжду сообщения от {len(ANSIBLE_TEST_LIST)} серверов\n(не забыть) /test_stop")

@app.on_message(filters.command("test_stop"))
async def stop_ansible_test(client, message):
    global ansible_test_active, ansible_test_results
    if message.chat.id in TARGET_CHATS or message.chat.id in LISTEN_CHATS:
        ansible_test_active = False
        
        # Формируем текст
        ok_count = list(ansible_test_results.values()).count("OK")
        fail_count = len(ansible_test_results) - ok_count
        
        report_text = (
            f"**Тестирование завершено**\n"
            f"Успешных тестов: {ok_count}\n"
            f"Не прошли тест: {fail_count}\n\n"
        )
        
        if fail_count > 0:
            report_text += "Сформирован отчет с тестами которые не прошли."
        else:
            report_text += "Тест успешно отработал (100% покрытие)"
            
        # механика генерации отчета
        report_filename = f"report_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.xlsx"
        generate_ansible_report(ansible_test_results, ANSIBLE_TEST_LIST, report_filename)
        
        # отправка сообщения в тг 
        await client.send_document(
            chat_id=message.chat.id,
            document=report_filename,
            caption=report_text
        )
        
        # удаление файла из сервера
        if os.path.exists(report_filename):
            os.remove(report_filename)

# ================= ПАРСЕР ЛОГОВ =================

@app.on_message(filters.chat(LISTEN_CHATS)) 
async def analyze_ssh_log(client, message):
    if not (message.from_user and message.from_user.is_bot): return 
    text = message.text or message.caption or ""
    if not text: return

    # Одиночные атаки
    if "Atak_" in text and "WEB_SRC_Atak_" not in text and "WEB_DST_Atak_" not in text:
        found_ip = re.search(r"Atak_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if found_ip:
            attack_ip = found_ip.group(1)
            
            if attack_ip in ATAK_SKIP_IPS:
                print(f"[log] Игнор одиночной Atak_ от {attack_ip} (в списке исключений ATAK_SKIP_IPS)", flush=True)
                return

            alert_reason = f"[Инцидент]: Зафиксирована SSH активность с IP: {attack_ip}"
            print(f"[!] АХТУНГ: {alert_reason}", flush=True)
            
            await save_alert(alert_reason, text, attack_ip)
            await register_incident(attack_ip, alert_reason)
            
            for chat in TARGET_CHATS:
                try:
                    await client.send_message(chat, f"***{alert_reason}***")
                    await message.copy(chat)
                except Exception as e: 
                    print(f"[!] Ошибка отправки: {e}", flush=True)
        return 
        
    if "WEB_SRC_Atak_" in text:
        found_ip = re.search(r"WEB_SRC_Atak_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if found_ip:
            src_ip = found_ip.group(1)
            
            if src_ip in ATAK_SKIP_IPS:
                print(f"[log] Игнор WEB_SRC_Atak от {src_ip} (в списке исключений)", flush=True)
                return

            zabbix_node = text.strip().split('\n')[0].strip()
            
            print(f"[*] Запуск таймера 60с для атаки SRC IP: {src_ip} (узел {zabbix_node})", flush=True)
            task = asyncio.create_task(wait_for_atak_resolution(client, src_ip, message))
            pending_attacks[zabbix_node] = task
        return 

    if "WEB_DST_Atak_" in text:
        found_ip = re.search(r"WEB_DST_Atak_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if found_ip:
            dst_ip = found_ip.group(1)
            
            if dst_ip in ATAK_SKIP_IPS:
                print(f"[log] Игнор WEB_DST_Atak на {dst_ip} (в списке исключений)", flush=True)
                return

            zabbix_node = text.strip().split('\n')[0].strip() 
            
            if zabbix_node in pending_attacks:
                print(f"[log] Получен DST IP: {dst_ip} (узел {zabbix_node}). Связка успешна, алерт отменен.", flush=True)
                pending_attacks[zabbix_node].cancel()
                del pending_attacks[zabbix_node]
            else:
                print(f"[log] Получен DST IP: {dst_ip}, но таймер SRC для {zabbix_node} не запускался.", flush=True)
        return 

    # ПЕРЕХВАТЧИК CPANEL 
    SKIP_KEYWORDS = ["Cpanel_SSH_Actiivty"]
    if any(key in text for key in SKIP_KEYWORDS):
        found_ip = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", text)
        if found_ip:
            ip_val = found_ip.group(1)
            if ip_val in CPANEL_SKIP_IPS:
                print(f"[log] игнор {ip_val} по системному ключу Cpanel", flush=True)
                return
            else:
                alert_reason = f"Подозрительная активность Cpanel с НЕИЗВЕСТНОГО IP: {ip_val}"
                print(f"[!] АХТУНГ: {alert_reason}", flush=True)
                await save_alert(alert_reason, text, ip_val)
                for chat in TARGET_CHATS:
                    try:
                        await client.send_message(chat, f"***{alert_reason}***")
                        await message.copy(chat)
                    except Exception as e: print(f"[!] Ошибка отправки: {e}", flush=True)
                return

    # СТАНДАРТНЫЙ ПАРСИНГ SSH 
    parsed = parse_ssh_message(text)
    user, ip, zabbix_name = parsed["user"], parsed["ip"], parsed["zabbix_name"]
    
    if not user or not ip:
        print(f"[log] Формат не SSH:\n{text}\n", flush=True)
        return 
    
    print(f"\n[log] юзер: {user} | Zabbix: {zabbix_name} | IP: {ip}", flush=True)
    
    alert_reason = None
    pair = (user, zabbix_name)

    # ЛОГИКА УСПЕШНОЙ АВТОРИЗАЦИИ 
    if parsed["is_success"]:
        last_success_time[ip] = datetime.now().timestamp()
        
        # ================= БЛОК ТЕСТИРОВАНИЯ ANSIBLE (ЛОГИКА "ИЛИ") =================
        if ansible_test_active:
            s_ip = parsed.get("server_ip")
            matched_key = None
            
            if zabbix_name in ANSIBLE_TEST_LIST:
                matched_key = zabbix_name
            else:
                for k, v in ANSIBLE_TEST_LIST.items():
                    if v == s_ip:
                        matched_key = k
                        break
                        
            if matched_key:
                ansible_test_results[matched_key] = "OK"
                print(f"[TEST] Успех: {matched_key} (Лог Zabbix: {zabbix_name}, IP: {s_ip})", flush=True)
        # ============================================================================
        
        if ip in pending_checks:
            pending_checks[ip].cancel()
            del pending_checks[ip]
        if ip in failed_attempts: failed_attempts[ip] = 0

        if pair in WATCH_LIST:
            print(f"[whatch_list]: {WATCH_LIST[pair]} [УСПЕХ]", flush=True)
            return
        
        if not alert_reason:
            if not is_working_hours(): alert_reason = "успешный вход в нерабочее время"
            elif user == "root" and not parsed["method_is_key"]: alert_reason = "root авторизовался НЕ по ключу"
            elif user != "root" and user not in ALLOWED_USERS: alert_reason = f"пользователь {user} не в списке разрешенных"

    # ЛОГИКА НЕУДАЧНОЙ АВТОРИЗАЦИИ 
    else:
        # ИММУНИТЕТ НА 5 МИНУТ если этот IP успешно заходил менее 5 минут назад (300 сек) игнорим опечатки
        if ip in last_success_time and (datetime.now().timestamp() - last_success_time[ip]) < 300:
            print(f"[log] Игнор ошибки для {ip}: пользователь уже сидит на сервере (успех менее 5 мин назад)", flush=True)
            return

        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

        if pair in WATCH_LIST:
            print(f"[whatch_list]: {WATCH_LIST[pair]} [НЕУДАЧА]", flush=True)
            if ip not in pending_checks:
                print(f"[*] Запуск таймера 60с для WATCH_LIST ({ip})", flush=True)
                task = asyncio.create_task(wait_for_watchlist_success(client, ip, message, WATCH_LIST[pair]))
                pending_checks[ip] = task
            return
            
        elif not alert_reason:
            if failed_attempts[ip] > 2:
                alert_reason = f"Обнаружено более 2-х неудачных попыток ({failed_attempts[ip]})"
                await register_incident(ip, alert_reason)

        if user not in IGNORE_BAD_IP_CLIENTS:
            if ip not in ALLOWED_IPS and not parsed["method_is_key"]:
                if ip not in pending_checks:
                    print(f"[*] Запуск таймера 60 сек для {ip}", flush=True)
                    task = asyncio.create_task(wait_for_success(client, ip, message))
                    pending_checks[ip] = task

    # ОТПРАВКА АЛЕРТА
    if alert_reason:
        print(f"[!] АХТУНГ: {alert_reason}", flush=True)
        await save_alert(alert_reason, text, ip)
        for chat in TARGET_CHATS:
            try:
                await client.send_message(chat, f"***{alert_reason}***")
                await message.copy(chat)
            except Exception as e: print(f"[!] Ошибка в {chat}: {e}", flush=True)

async def start_bot():
    print("Подключение к базе данных PostgreSQL", flush=True)
    await init_db()
    
    await app.start()
    print("Бот запущен. Скан начат.", flush=True)
    
    startup_msg = "IDS Бот успешно запущен/перезагружен"
    for chat in TARGET_CHATS:
        try:
            await app.send_message(chat, startup_msg)
        except Exception as e:
            print(f"[!] Не удалось отправить сообщение о старте в {chat}: {e}")

    from pyrogram import idle
    await idle()
    
    shutdown_msg = "IDS БОТ остановлен (выключен контейнер)"
    for chat in TARGET_CHATS:
        try:
            await app.send_message(chat, shutdown_msg)
        except Exception as e:
            pass

    await app.stop()

if __name__ == "__main__":
    try: 
        app.loop.run_until_complete(start_bot())
    except KeyboardInterrupt:
        print("Бот остановлен вручную.")
    except Exception as e: 
        print(f"Критическая ошибка: {e}")
