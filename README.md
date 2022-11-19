# Honeypot Assignment

**Time spent:** **10** hours spent in total

**Objective:** Create a honeynet using MHN-Admin. Present your findings as if you were requested to give a brief report of the current state of Internet security. Assume that your audience is a current employer who is questioning why the company should allocate anymore resources to the IT security team.

### MHN-Admin Deployment (Required)

**Summary:** 

I used the Google Cloud Platform to set up all honeypots shown below. Through the Google SDK Shell I used the subsequent multi-line commands to enable the required inbound ports for MHN Admin.

gcloud compute firewall-rules create http \
    --allow tcp:80 \
    --description="Allow HTTP from Anywhere" \
    --direction ingress \
    --target-tags="mhn-admin"

gcloud compute firewall-rules create honeymap \
    --allow tcp:3000 \
    --description="Allow HoneyMap Feature from Anywhere" \
    --direction ingress \
    --target-tags="mhn-admin"

gcloud compute firewall-rules create hpfeeds \
    --allow tcp:10000 \
    --description="Allow HPFeeds from Anywhere" \
    --direction ingress \
    --target-tags="mhn-admin"

Next step was to create the instance (mhn-admin): 

gcloud compute instances create "mhn-admin" \
    --machine-type "n1-standard-1" \
    --subnet "default" \
    --maintenance-policy "MIGRATE" \
    --tags "mhn-admin" \
    --image-family "ubuntu-minimal-1804-lts" \
    --image-project "ubuntu-os-cloud" \
    --boot-disk-size "10" \
    --boot-disk-type "pd-standard" \
    --boot-disk-device-name "mhn-admin"
    
 
    Using the GCP I was able to SSH into the instance to install the MHN admin software using the subsequent multi-line commands:
    
    To update the instance & to install python to execute the install:
    sudo apt update
    sudo apt install git python-magic -y   
    
    Next we change directories to /opt/ and clone the pwnlandia/mhn.git github repository. Afterwards I changed directories to /mhn/ to patch the python         package requirement files and then run the install:

    cd /opt/
    sudo git clone https://github.com/pwnlandia/mhn.git
    cd mhn/

    sudo sed -i 's/Flask-SQLAlchemy==2.3.2/Flask-SQLAlchemy==2.5.1/g' server/requirements.txt

    sudo ./install.sh    
    
    After executing the install you will be presented with the following options: 
    
    Do you wish to run in Debug mode? y/n : n
    Superuser email: You can use any email -- this will be your username to login to the admin console.
    Superuser password: Choose any password -- you'll be asked to confirm.
    
    Accept the default values :

    Server base url ["http://#.#.#.#"]:
    Honeymap url ["http://#.#.#.#:3000"]:
    Mail server address ["localhost"]:
    Mail server port [25]:
    Use TLS for email?: y/n n
    Use SSL for email?: y/n n
    Mail server username [""]:
    Mail server password [""]:
    Mail default sender [""]:
    Path for log file ["/var/log/mhn/mhn.log"]:
    
    Next:
    Would you like to integrate with Splunk? (y/n) n
    Would you like to install ELK? (y/n) n
    
    and lastly..

    Would you like to add MHN rules to UFW? (y/n) n
    
    We can successfully log into our MHN Administrator by visiting the external ip of our mhn-admin instance and using the previously configured credentials. 

![MHN admin set up ](https://user-images.githubusercontent.com/111711434/202872609-6fd47632-eb91-4d7f-896f-fdaf93366c6e.gif)

### Dionaea Honeypot Deployment (Required)

**Summary:** Briefly in your own words, what does dionaea do?

Dionaea is a malware trapping honeypot which mimics exploitable services on a server to capture a copy of the malware. This particular honeypot captures malware using Server Message Block(SMB), Hyper Text Transfer Protocol (HTTP), File Transport Protocol(FTP), Trivial File Transfer Protocol (TFTP), Microsoft SQL Server (MSSQL) and Voice over IP (VoIP) Protocols. Dionaea is able to capture a copy of the malware using LibEmu; which will detect, measure, and if necessary, execute the measuring/profiling shellcode. 

To deploy dionaea we will first create an instance using the following command in our Google SDK:

Create a firewall rule to allow incoming TCP and UDP traffic on all ports for honeypot sensors:
gcloud compute firewall-rules create wideopen \
    --description="Allow TCP and UDP from Anywhere" \
    --direction ingress \
    --priority=1000 \
    --network=default \
    --action=allow \
    --rules=tcp,udp \
    --source-ranges=0.0.0.0/0 \
    --target-tags="honeypot"
    
Create the instance:
gcloud compute instances create "honeypot-1" \
    --machine-type "n1-standard-1" \
    --subnet "default" \
    --maintenance-policy "MIGRATE" \
    --tags "honeypot-1" \
    --image-family "ubuntu-minimal-1804-lts" \
    --image-project "ubuntu-os-cloud" \
    --boot-disk-size "10" \
    --boot-disk-type "pd-standard" \
    --boot-disk-device-name "honeypot-1"
    
    Next we will go back to our MHN administator portal and access the 'Deploy' section, under New Script, select Dionaea and the 'wget' command generates:
    wget "http://34.125.119.88/api/script/?text=true&script_id=2" -O deploy.sh && sudo bash deploy.sh http://34.125.119.88 iocoAQpK
    
    Run this command in your honeypot-1 instance and the sensor is now added. 

![Dionaea deployment](https://user-images.githubusercontent.com/111711434/202873486-dc4414e0-b633-440c-8265-4a6b25b54c31.gif)
### Database Backup (Required) 

**Summary:** What is the RDBMS that MHN-Admin uses? What information does the exported JSON file record?

  The MHN-admin uses MongoDB as its RDMBS. MongoDB was used to export the Dionaea report log via the following subsuquent commands: 

 - mongoexport --db mnemosyne --collection session > session.json com
 - gcloud compute scp mhn-admin:~/session.json ./session.json


The information provided in the session.json file is a log for the dionaea sensor which contained the information seen below: 

{"_id":{"$oid":"637304c9616a1e64ea05165c"},"protocol":"pcap","hpfeed_id":{"$oid":"637304c9616a1e64ea05165b"},"timestamp":{"$date":"2022-11-15T03:17:29.929Z"},"source_ip":"67.38.13.12","source_port":61760,"destination_port":3389,"identifier":"406359f8-6493-11ed-ba5a-42010ab60007","honeypot":"dionaea"}
.... continued


### Deploying Additional Honeypot(s) (Optional)

#### Snort Honeypot
I deployed this honeypot using the before mentioned method:

Created instance: 
gcloud compute instances create "honeypot-2" \
    --machine-type "n1-standard-1" \
    --subnet "default" \
    --maintenance-policy "MIGRATE" \
    --tags "honeypot-2" \
    --image-family "ubuntu-minimal-1804-lts" \
    --image-project "ubuntu-os-cloud" \
    --boot-disk-size "10" \
    --boot-disk-type "pd-standard" \
    --boot-disk-device-name "honeypot-2"

Deployed the Sensor:
wget "http://34.125.119.88/api/script/?text=true&script_id=4" -O deploy.sh && sudo bash deploy.sh http://34.125.119.88 iocoAQpK


**Summary:** What does this honeypot simulate and do for a security researcher?

Snort is а nеtwork intrusion dеtеction systеm , а pаckеt sniffеr thаt cаpturеs аnd scаns nеtwork trаffic in rеаl timе, еxаmining еаch packet closely to dеtеct аn intrusion. [1] It combinеs аbnormаl bеhаviour dеtеction signаturеs аnd diffеrеnt mеthods of protocol dеtеction.[2] This allows for security researchers to look at the logs and prepare defenses from lessons learned in the honeypot to the actual server. 

![Snort Deployment](https://user-images.githubusercontent.com/111711434/202874439-765a6fd3-dbc3-413c-8b9a-0771e8121b53.gif)

sources cited: https://www.irjet.net/archives/V6/i2/IRJET-V6I290.pdf
#### p0f Honeypot

![p0f honeypot](https://user-images.githubusercontent.com/111711434/202874834-037e11fe-d8a7-4bd8-ac56-90a3436048dc.gif)


### Malware Capture and Identification (Optional)

#### Worm.Win32.VB.cj Malware

**Summary:** How did you find it? Which honeypot captured it? What does each malware do?

Captured using p0f; this particular worm spreads using Peer-to-Peer-networks and it also tries to disable several applications on infected system.

The worm installs the following registry key for ensuring it will be started in the next system startup:

[HKLM\Software\Microsoft\Windows\CurrentVersion\Run]
"winupdates" = "%ProgramFiles%\winupdates\winupdates.exe"
 
The worm also writes the following files to the Windows system folder:

cmd.com
regedit.com
taskkill.com
tasklist.com
tracert.com
ping.com
netstat.com


source: https://www.f-secure.com/v-descs/vb_an.shtml

MD5 Hash: 002f05020cc7f7ea235ad4bbec592b825a9e4aed56498d8fdc0d7dc57ef67c0e

SHA1 Hash:  5c0e54f50c654d50bec84919e4739b00b0833ba0 


## Attacking the Honeypot

To go the extra mile I also performed succesful synflood via the msfconsole on one honeypot which resulted in Denial of Service:
![Synflood DOS honeypot-3](https://user-images.githubusercontent.com/111711434/202874868-577ab7c8-9e1d-4374-aa13-416017472633.gif)

## Notes

Ran into an issue where the gcloud compute scp mhn-admin:~/session.json ./session.json was not working with the proper directory either. I resolved it by using the SSH feature in the Google Cloud Platform, at the top right you have the option to download files, all you have to do is offer the full path directory(you may obtain it by using command: pwd). 
![image](https://user-images.githubusercontent.com/111711434/202874831-646530fc-f1b6-4128-88d1-7dc804160ae9.png)

