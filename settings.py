
"""
    Crowdstrike API configurations.
"""
client_id = ""
client_secret = ""
crowdstrike_url = ""

"""
    MISP configurations.
"""
misp_url = ""
misp_auth_key = ""
crowdstrike_org_uuid = ""

"""
        Mapping used to map the malware families in Crowdstrike Intel API to MISP galaxies.
        https://www.misp-project.org/galaxy.html
"""
malware_family_to_galaxy_mapping = {
    "njRAT": 'misp-galaxy:malpedia="NjRAT"',
    "Qakbot": 'misp-galaxy:banker="Qakbot"',
    "Tinba": 'misp-galaxy:banker="Tinba"',
    "Nymaim": 'misp-galaxy:malpedia="Nymaim"',
    "Pony": 'misp-galaxy:malpedia="Pony"',
    "Sakula": 'misp-galaxy:rat="Sakula"',
    "LokiBot": 'misp-galaxy:android="LokiBot"',
    "DarkComet": 'misp-galaxy:malpedia="DarkComet"',
    "GandCrab": 'misp-galaxy:malpedia="Gandcrab"',
    "Geodo": 'misp-galaxy:banker="Geodo"',
    "PoisonIvy": 'misp-galaxy:malpedia="Poison Ivy"',
    "Kovter": 'misp-galaxy:malpedia="Kovter"',
    "CoreBot": 'misp-galaxy:banker="Corebot"',
    "Emotet": 'misp-galaxy:malpedia="Emotet"',
    "X-Agent": 'misp-galaxy:tool="X-Agent"',
    "Gozi": 'misp-galaxy:banker="Gozi"',
    "ISFB": 'misp-galaxy:malpedia="ISFB"',
    "Andromeda": 'misp-galaxy:malpedia="Andromeda"',
    "Kronos": 'misp-galaxy:malpedia="Kronos"',
    "AgentTesla": 'misp-galaxy:tool="Agent Tesla"',
    "Azorult": 'misp-galaxy:malpedia="Azorult"',
    "Rifdoor": 'misp-galaxy:malpedia="Rifdoor"',
    "Ursnif": 'misp-galaxy:mitre-malware="Ursnif - S0386"',
    "FormBook": 'misp-galaxy:malpedia="Formbook"',
    "XtremeRAT": 'misp-galaxy:rat="XtremeRAT"',
    "Excalibur": 'misp-galaxy:malpedia="Excalibur"',
    "Sekur": 'misp-galaxy:tool="Sekur"',
    "Netwire": 'misp-galaxy:rat="Netwire"',
    "Dridex": 'misp-galaxy:tool="Dridex"',
    "URLZone": 'misp-galaxy:malpedia="UrlZone"',
    "SolarBot": 'misp-galaxy:malpedia="Solarbot"',
    "Gh0stRAT": 'misp-galaxy:tool="Gh0st Rat"',
    "Taleret": 'misp-galaxy:malpedia="Taleret"',
    "Badnews": 'misp-galaxy:malpedia=BadNews',
    "SmokeLoader": 'misp-galaxy:malpedia=SmokeLoader',
    "Quasar": 'misp-galaxy:malpedia=Quasar RAT',
    "LummaStealer": 'misp-galaxy:malpedia=Lumma Stealer',
    "Mofksys": 'misp-galaxy:malpedia=Mofksys',
    "RisePro": 'misp-galaxy:malpedia=RisePro',
    "Salityv3": 'misp-galaxy:malpedia=Sality',
    "Salityv4": 'misp-galaxy:malpedia=Sality',
    "Sality": 'misp-galaxy:malpedia=Sality',
    "Octo": 'misp-galaxy:malpedia=Coper',
    "RedLineStealer": 'misp-galaxy:malpedia=RedLine Stealer',
    "NanoCore": 'misp-galaxy:malpedia=NanoCore',
    "STOP": 'misp-galaxy:malpedia=STOP',
    "MysticStealer": 'misp-galaxy:malpedia=Mystic Stealer',
    "Stealc": 'misp-galaxy:malpedia=Stealc',
    "Tofsee": 'misp-galaxy:malpedia=Tofsee',
    "JasperLoader": 'misp-galaxy:malpedia=JasperLoader',
    "RisePro": 'misp-galaxy:malpedia=RisePro',
    "CobaltStrike": 'misp-galaxy:malpedia=CobaltStrike',
    "AsyncRAT": 'misp-galaxy:malpedia=AsyncRAT',
    "Rhadamanthys": 'misp-galaxy:malpedia=Rhadamanthys',
    "Vflooder": 'misp-galaxy:malpedia=Vflooder',
    "Warzone": "misp-galaxy:malpedia=WarzoneRAT",
    "Nitol": "misp-galaxy:malpedia=Nitol",
    "Xworm": "misp-galaxy:malpedia=Xworm",
    "Remcos": "misp-galaxy:malpedia=Remcos"
}

"""
    Device ids that you want to import detections from.
"""
device_ids=[]

"""
    Confidence and Severity to use to filter out the detections.
"""
confidence = '10'
severity = '10'