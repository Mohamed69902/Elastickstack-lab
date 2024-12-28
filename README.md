# Building detection lab with ELASTIC-STACK

## Objective

This project demonstrates how to use Elastic Stack (ELK) for incident response. It simulates security incidents on both Linux and Windows systems, showing how Elasticsearch, Logstash, and Kibana can be used to collect, analyze, and visualize logs. The goal is to install Elasticstack, configure it, and provide a practical example of how Elastic Stack helps in detecting and responding to cybersecurity threats.

### Skills Learned

- Building a virtual enviroment. 
- Installing elastic search, kibana, logstach, and configure them.
- Deploying agents in Vm client, such as winlogbeat, packetbeat, elastic-agent.
- Visualizeing logs recieved from the agents.
- Incident detection with elastic deffend alerts.
  
### Tools Used


- Virtualbox (setting up the virtual enviroment).
- Winrar (Merging a payload with an image).
- Winscp (Moving files between VMs).
- Putty.

### Diagram 
![Diagramme sans nom](https://github.com/user-attachments/assets/129c781e-2e0b-47a4-acd0-0d2fd67723c4)



## Steps
 ### Step1 - Installing Ubutu server 24.04.1 LTS
  #### System configuration :
      -8Gb ram
      -100Gb storage
      -3 cores
  #### Network configuration :
      -Bridged adapter
      -Ip : 192.168.1.234
      -subnet mask : 255.255.255.0
![UBUNTU SERVER](https://github.com/user-attachments/assets/5f2c76aa-572f-4c87-a338-43f7b250d6ac)
### Step2 - Install & configure Elatick Search 
  #### 1. Download & Install Elastic Stack (commands used):
      wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
	    sudo apt-get install apt-transport-https
	    echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main"
      sudo tee /etc/apt/sources.list.d/elastic-8.x.list
	    sudo apt-get update && sudo apt-get install elasticsearch

     
  #### 2. Check Elastic search service & Reset Elastic password:
      systemctl start elasticsearch
	    systemctl status elasticsearch
	    cd /usr/share/elasticsearch/bin
	    ./elasticsearch-reset-password -i -u elastic

  #### 3. Configure Elastic Configuration File:
      sudo nano /etc/elasticsearch/elasticsearch.yml
	    cluster.name: my_network (Optional)
	    network.host: http://192.168.1.234  (Real Host Name)
	    http.port: 9200          (Do Not Change)
  ![elaticsearchconfig](https://github.com/user-attachments/assets/30f21958-a486-4635-82d6-bd24b09d4781)

     
  #### 4. Connect To Elastic Search Port :
      ss -ntpl
	    https://192.168.1.243:9200 

  #### 5. Enabled elasticsearch Start on Boot:
      sudo systemctl enable elasticsearch
	    sudo systemctl start elasticsearch
	    sudo systemctl status elasticsearch
![elasticsearch service](https://github.com/user-attachments/assets/a8227718-1100-418d-994d-b0eca853cf6a)


### Step2 - Enable SSL certificate for elastic search:
  #### 1. Create CA File :
      cd /usr/share/elasticsearch/bin
	    sudo ./elasticsearch-certutil ca --pem --out /etc/elasticsearch/certs/ca.zip
	    cd /etc/elasticsearch/certs
	    apt install unzip
	    sudo unzip ca.zip
  #### 2. Create Certificate For Elastic :
      cd /usr/share/elasticsearch/bin
	    sudo ./elasticsearch-certutil cert --out /etc/elasticsearch/certs/elastic.zip --name elastic --ca-cert /etc/elasticsearch/certs/ca/ca.crt --ca-key /etc/elasticsearch/certs/ca/ca.key --dns elastic --pem
	    cd /etc/elasticsearch/certs
	    sudo unzip elastic.zip
  ![certs-elasticsearch](https://github.com/user-attachments/assets/c207401b-931c-422f-924c-824094ae416f)

  #### 3. Enable Certificate in Elastic Configuration File :
      sudo nano /etc/elasticsearch/elasticsearch.yml
	    Uncomment #keystore.path: certs/http.p12
	     enabled: true
	     certificate: certs/elastic/elastic.crt
	     key: certs/elastic/elastic.key
	     certificate_authorities: certs/ca/ca.crt
	    cd /etc/elasticsearch
	    ls -alh certs/ca
	    chown -R elasticsearch:elasticsearch .
	    ls -alh certs/ca
	    sudo systemctl restart elasticsearch.service
	    sudo systemctl status elasticsearch.service
  ![CERTIFICATE-CONFIG](https://github.com/user-attachments/assets/3c83bb81-f3df-42e6-aacc-8ec943ec7ada)
### Step3 - Install & Configure Kibana On Ubuntu:
  #### 1. Install Kibana :
       apt-get install kibana -y
	     sudo nano /etc/kibana/kibana.yml
	     uncomment : server.host: "0.0.0.0"
	     uncomment : server.port: 5601
	     uncomment : server.publicBaseUrl: "https://elkserver:5601"
  #### 2. Create Certificate For Kibana:
       cd /usr/share/elasticsearch/bin
	     sudo ./elasticsearch-certutil cert --out /etc/kibana/kibana.zip --name kibana --ca-cert /etc/elasticsearch/certs/ca/ca.crt --ca-key /etc/elasticsearch/certs/ca/ca.key --dns kibana --pem
	     cd /etc/kibana
	     sudo unzip kibana.zip 
	     cp /etc/elasticsearch/certs/ca/ca.crt /etc/kibana/kibana
	     cd /etc/kibana/kibana
	     ls -alh
	     chown -R kibana:kibana ./
	     ls -alh
	     ls -alh kibana
  #### 3. Enable Certificate in Kibana Configuration File:
       sudo nano /etc/kibana/kibana.yml
	     uncomment : server.ssl.enabled: true
			 server.ssl.certificateAuthorities: [ "/etc/kibana/kibana/ca.crt" ]
			 server.ssl.certificate: /etc/kibana/kibana/kibana.crt
			 server.ssl.key: /etc/kibana/kibana/kibana.key
			 elasticsearch.hosts: ["https://elkserver:9200"]
  ![KIBANASSL](https://github.com/user-attachments/assets/df032f0f-b05c-47f3-9bdb-9542d4e0916f)

  #### 4. Enable  Create Account Token:
       cd /usr/share/elasticsearch/bin/
	     sudo ./elasticsearch-service-tokens create elastic/kibana kibana_token
	     cd /etc/elasticsearch
	     chown -R elasticsearch:elasticsearch service_tokens
	     ls -alh
	     sudo nano /etc/kibana/kibana.yml
	     uncomment : elasticsearch.serviceAccountToken: "AAEAAWVsYXN0aWMva2liYW5hL2tpYmFuYV90b2tlbjoxMHRuZzBJUlJZUzYwcnhaZlNPRU13"
	     elasticsearch.ssl.verificationMode: none 
	     xpack.encryptedSavedObjects.encryptionKey: "put 32 char"
  #### 5. Start Kibana Start On Boot:
      sudo systemctl enable kibana
	    sudo systemctl start kibana
	    sudo systemctl status kibana
  ![KIBANA SERVICE](https://github.com/user-attachments/assets/5f8bc34f-9810-41ae-8f77-ec1da6f1cc12)

  ![kibana-ui](https://github.com/user-attachments/assets/c8c4b7ba-bd79-45fc-96cb-a130f413f8f8)
### Step4 - Installing Fleet Server & File Beat:
  #### 1 Installing Elastic Agent :
     apt install elastic-agent -y
	   systemctl enable elastic-agent
  #### 2. Add & Configure Fleet Server :
    Open Fleet Page > Setting > Edite Elastic Host : https://<IP>:9200 > ssl.verification_mode: "none"
	  Add Fleet Server > Click On Settings > https://<IP>:8220 > Advanced > Generate Fleet Server Token > 
  		sudo elastic-agent enroll --url=https://192.168.1.243:8220 \
  		--fleet-server-es=https://192.168.1.243:9200 \
  		--fleet-server-service-token= Your_Token_Here \
  		--fleet-server-policy=fleet-server-policy \
  		--certificate-authorities=/etc/kibana/kibana/ca.crt \
  		--fleet-server-es-ca=/etc/kibana/kibana/ca.crt \
  		--fleet-server-cert=/etc/kibana/kibana/kibana.crt \
  		--fleet-server-cert-key=/etc/kibana/kibana/kibana.key \
  		--fleet-server-port=8220 \
  		--insecure
  	 systemctl start elastic-agent
  #### 3. Filebeat Threat Intel module :
     apt install filebeat -y
	   filebeat modules enable threatintel
	   sudo nano /etc/filebeat/modules.d/threatintel.yml :
   		  MISP: false
   		  OTX:false
		 uncomment the following :	
	 	    var.username: guest
     		var.password: guest
 	    sudo nano /etc/filebeat/filebeat.yml :
	    uncomment out the username and password & type password for elastic accouont
      add the following line : ssl.verification_mode: none : under elastic search output section
   	 	uncomment  protocol: "https" under elastic search output section
 	 	  uncomment > host: "https://192.168.1.243:5601" > under kibana section
	  	add the following line > ssl.verification_mode: none > under kibana section


      filebeat test config
      filebeat test output
      sudo filebeat setup
      systemctl enable filebeat
      systemctl start filebeat

  ![filebeat](https://github.com/user-attachments/assets/64ced62d-5c6e-4120-873c-063428db2317)
  ### Step6. Install WinlogBeat Agent On Windows  :
   #### 1.Enable Power shell Logging :
     function Enable-PSScriptBlockLogging{$basePath = 'HKLM:\Software\Policies\Microsoft\Windows' +'\PowerShell\ScriptBlockLogging'if(-not (Test-Path $basePath)){$null = New-Item $basePath -Force} Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value "1"}
  #### 2. Install Winlog Beat On Windows Client:
     https://www.elastic.co/downloads/beats/winlogbeat
     Extract ZIP File to program files > run cmd as admin > cd winlogbeat colder
     winlogbeat.exe keystore create > winlogbeat.exe keystore add ES_PWD
     notepad.exe winlogbeat.yml :
	     - Kibana Section : 
	     - Uncomment : host: "https://192.168.1.243:5601"
	     - Add ssl.verification_mode: none
	     - Elasticsearch Output:
	     - hosts: ["https://192.168.1.243:9200"] 
	     - Uncomment username: "elastic" & Uncomment password: "${ES_PWD}"
	     - Add ssl.verification_mode: none
    winlogbeat.exe test config 
    winlogbeat.exe test output
    winlogbeat.exe setup
    PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
    Md c:\ProgramData\winlogbeat 
    copy "C:\Program Files\winlogbeat-{version}-windows-x86_64\data\winlogbeat.keystore" c:\ProgramData\winlogbeat\
    Run "winlogbeat" service

  #### 3. Install PacketBeat Agent On Windows:
    Extract ZIP File to program files > run cmd as admin > cd packetbeat colder
    packetbeat.exe keystore create > packetbeat.exe keystore add ES_PWD
    packetbeat.exe devices
    notepad.exe packetbeat.yml :
	    - interfaces.device: 0
	    - Kibana Section : 
	    - Uncomment : host: "https://192.168.1.243:5601"
	    - Add ssl.verification_mode: none
	    - Elasticsearch Output:
	    - hosts: ["https://192.168.1.243:9200"] 
	    - Uncomment username: "elastic" & Uncomment password: "${ES_PWD}"
	    - Add ssl.verification_mode: none
    packetbeat.exe test config 
    packetbeat.exe test output
    packetbeat.exe setup
    PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-packetbeat.ps1 
    Md c:\ProgramData\packetbeat 
    copy "C:\Program Files\packetbeat-8.12.2\data\packetbeat.keystore" c:\ProgramData\packetbeat
    Run "packetbeat" service
    Netstat -n
![winlogbeat-packetbeat](https://github.com/user-attachments/assets/299cf846-2b0e-4b9e-9d02-9718c2f01f15)
### Step5 - Install Elastic Security Endpoint On Windows:
 #### 1. Install sysmon Service:
    Microsoft Sysmon Internals
      https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    Sysmon Configuration File
      https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml
    Sysmon64.exe -i config-file.xml 
    Run sysmon64 service
    Check windows logs are generated from sysmon
#### 2.  Add Windows Policy Fleet Server:
    Fleet > agent policies > create agent policy : Windows & Unchecked  system metrics
    Add Integration > Windows & Elastic Defend 
#### 3.  Add Elastic Agent For Windows:
    Download Elastic Agent for windows & extract files to program files
    Open powershell as admin
    Go to elastic agent path 
    Run install commands with --insecure flag
    Add ssl.verification_mode: "none" in fleet server settings
![agents](https://github.com/user-attachments/assets/edac342c-b966-45f3-9c7b-226ec80b37e6)

#### 4.  Enabling Elastic Security Endpoint Rules :
    Open Security > rules > Detection Rules
  ![rules](https://github.com/user-attachments/assets/a3cb35e6-7b20-4525-9077-221a2ff2cd0b)





 

