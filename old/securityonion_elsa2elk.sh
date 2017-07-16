#!/bin/bash
# Convert Security Onion ELSA to ELK

# Check for prerequisites
if [ "$(id -u)" -ne 0 ]; then
	echo "This script must be run using sudo!"
	exit 1
fi

for FILE in /etc/nsm/securityonion.conf /etc/nsm/sensortab; do
	if [ ! -f $FILE ]; then
		echo "$FILE not found!  Exiting!"
		exit 1
	fi
done

if ! grep -i "ELSA=YES" /etc/nsm/securityonion.conf > /dev/null 2>&1 ; then
	echo "ELSA is not enabled!  Exiting!"
	exit 1
fi

if [ -f /root/.ssh/securityonion_ssh.conf ]; then
	echo "This script can only be executed on boxes running in Evaluation Mode.  Exiting!"
	exit 1
fi

SENSOR=`grep -v "^#" /etc/nsm/sensortab | tail -1 | awk '{print $1}'`
if ! grep 'PCAP_OPTIONS="-c"' /etc/nsm/$SENSOR/sensor.conf > /dev/null 2>&1 ; then
	echo "This script can only be executed on boxes running in Evaluation Mode.  Exiting!"
	exit 1
fi

clear
cat << EOF 
This QUICK and DIRTY script is designed to allow you to quickly and easily experiment with ELK (Elasticsearch, Logstash, and Kibana) on Security Onion.

This script assumes that you've already installed and configured the latest Security Onion 14.04.5.2 ISO image as follows:
* (1) management interface with full Internet access
* (1) sniffing interface (separate from management interface)
* Setup run in Evaluation Mode to enable ELSA

This script will do the following:
* install OpenJDK 7 from Ubuntu repos (we'll move to OpenJDK 8 when we move to Ubuntu 16.04)
* download ELK packages from Elastic
* install and configure ELK
* import our custom visualizations and dashboards
* disable ELSA
* configure syslog-ng to send logs to Logstash on port 6050
* configure Apache as a reverse proxy for Kibana and authenticate users against Sguil database
* update CapMe to leverage that single sign on and integrate with ELK
* replay sample pcaps to provide data for testing

Depending on the speed of your hardware and Internet connection, this process will take at least 10 minutes.

TODO
* remove ELSA cron job /etc/cron.d/elsa
* tag snort logs correctly
* control ES disk usage
* add script to wipe ES
* update logstash patterns for Bro 2.5 (ssh, smtp, intel, and http) and convert from grok to csv where possible
* configure CapMe to detect BRO_PE / BRO_X509 and pivot to BRO_FILES via FID and then to BRO_CONN via CID
* configure Sguil client to pivot from IP address to Kibana search for that IP
* configure Squert and Sguil to query ES directly
* build our own ELK packages hosted in our own PPA

HARDWARE REQUIREMENTS
ELK requires more hardware than ELSA, so for a test VM, you'll probably want at LEAST 2 CPU cores and 4GB of RAM.

THANKS
Special thanks to Justin Henderson for his Logstash configs and installation guide!
https://github.com/SMAPPER/Logstash-Configs

Special thanks to Phil Hagen for all his work on SOF-ELK!
https://github.com/philhagen/sof-elk

WARNINGS AND DISCLAIMERS
* This technology PREVIEW is PRE-ALPHA, BLEEDING EDGE, and TOTALLY UNSUPPORTED!
* If this breaks your system, you get to keep both pieces!
* This script is a work in progress and is in constant flux.
* This script is intended to build a quick prototype proof of concept so you can see what our ultimate ELK configuration might look like.  This configuration will change drastically over time leading up to the final release.
* Do NOT run this on a system that you care about!
* Do NOT run this on a system that has data that you care about!
* This script should only be run on a TEST box with TEST data!
* This script is only designed for standalone boxes and does NOT support distributed deployments.
* Use of this script may result in nausea, vomiting, or a burning sensation.
 
Once you've read all of the WARNINGS AND DISCLAIMERS above, please type AGREE to proceed:
EOF
read INPUT
if [ "$INPUT" != "AGREE" ] ; then exit 0; fi

# Make a directory to store downloads
DIR="/tmp/elk"
mkdir $DIR
cd $DIR

# Define a banner to separate sections
banner="========================================================================="

header() {
	echo
	printf '%s\n' "$banner" "$*" "$banner"
}

header "Installing OpenJDK"
apt-get update > /dev/null
apt-get install openjdk-7-jre-headless -y

header "Downloading ELK packages"
wget https://download.elastic.co/elasticsearch/release/org/elasticsearch/distribution/deb/elasticsearch/2.4.4/elasticsearch-2.4.4.deb
wget https://download.elastic.co/logstash/logstash/packages/debian/logstash-2.4.1_all.deb
wget https://download.elastic.co/kibana/kibana/kibana-4.6.4-amd64.deb
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | apt-key add -

header "Installing ELK packages"
dpkg -i /tmp/elk/elasticsearch-*.deb
dpkg -i /tmp/elk/logstash-*_all.deb
dpkg -i /tmp/elk/kibana-*-amd64.deb

header "Downloading GeoIP data"
mkdir /usr/local/share/GeoIP
cd /usr/local/share/GeoIP
rm Geo*.dat
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
gunzip *.gz
cd $DIR

header "Installing ELK plugins"
apt-get install git python-pip -y
pip install elasticsearch-curator
/usr/share/elasticsearch/bin/plugin install lmenezes/elasticsearch-kopf
/opt/logstash/bin/logstash-plugin install logstash-filter-translate
/opt/logstash/bin/logstash-plugin install logstash-filter-tld
/opt/logstash/bin/logstash-plugin install logstash-filter-elasticsearch
/opt/logstash/bin/logstash-plugin install logstash-filter-rest
/opt/kibana/bin/kibana plugin --install elastic/sense
/opt/kibana/bin/kibana plugin --install prelert_swimlane_vis -u https://github.com/prelert/kibana-swimlane-vis/archive/v0.1.0.tar.gz
git clone https://github.com/oxalide/kibana_metric_vis_colors.git
apt-get install zip -y
zip -r kibana_metric_vis_colors kibana_metric_vis_colors
/opt/kibana/bin/kibana plugin --install metric-vis-colors -u file://$DIR/kibana_metric_vis_colors.zip
/opt/kibana/bin/kibana plugin -i kibana-slider-plugin -u https://github.com/raystorm-place/kibana-slider-plugin/releases/download/v0.0.2/kibana-slider-plugin-v0.0.2.tar.gz
/opt/kibana/bin/kibana plugin --install elastic/timelion
/opt/kibana/bin/kibana plugin -i kibana-html-plugin -u https://github.com/raystorm-place/kibana-html-plugin/releases/download/v0.0.3/kibana-html-plugin-v0.0.3.tar.gz

header "Downloading Config Files"
if [ "$1" == "dev" ]; then
	URL="https://github.com/dougburks/elk-test.git"
else
	URL="https://github.com/Security-Onion-Solutions/elk-test.git"
fi
git clone $URL

header "Configuring ElasticSearch"
FILE="/etc/elasticsearch/elasticsearch.yml"
cp $FILE $FILE.bak
cp elk-test/elasticsearch/elasticsearch.yml $FILE
mkdir -p /nsm/es/securityonion
chown -R elasticsearch:elasticsearch /nsm/es
echo "Done!"

header "Configuring Logstash"
cp -rf elk-test/configfiles/*.conf /etc/logstash/conf.d/
cp -rf elk-test/dictionaries /lib/
cp -rf elk-test/grok-patterns /lib/
echo "Done!"

header "Configuring Kibana"
FILE="/opt/kibana/config/kibana.yml"
cp $FILE $FILE.bak
cp elk-test/kibana/kibana.yml $FILE
echo "Done!"

header "Configuring Apache to reverse proxy Kibana and authenticate against Sguil database"
cp elk-test/proxy/securityonion.conf /etc/apache2/sites-available/
cp elk-test/proxy/so-apache-auth-sguil /usr/local/bin/
cp -av elk-test/proxy/so/* /var/www/so/
apt-get install libapache2-mod-authnz-external -y
a2enmod auth_form
a2enmod request
a2enmod session_cookie
a2enmod session_crypto
FILE="/etc/apache2/session"
< /dev/urandom tr -dc A-Za-z0-9 | head -c${1:-32} >> $FILE
chown www-data:www-data $FILE
chmod 660 $FILE
ln -s ssl-cert-snakeoil.pem /etc/ssl/certs/securityonion.pem
ln -s ssl-cert-snakeoil.key /etc/ssl/private/securityonion.key

header "Enabling and Starting ELK"
update-rc.d elasticsearch defaults
update-rc.d logstash defaults
update-rc.d kibana defaults
service elasticsearch start
service logstash start
service kibana start

header "Waiting for Logstash to initialize"
max_wait=240
wait_step=0
until nc -vz localhost 6050 > /dev/null 2>&1 ; do
	wait_step=$(( ${wait_step} + 1 ))
	if [ ${wait_step} -gt ${max_wait} ]; then
		echo "ERROR: logstash not available for more than ${max_wait} seconds."
		exit 5
	fi
	sleep 1;
	echo -n "."
done
echo

header "Updating CapMe to integrate with ELK"
cp -av elk-test/capme /var/www/so/

header "Disabling ELSA"
FILE="/etc/nsm/securityonion.conf"
sed -i 's/ELSA=YES/ELSA=NO/' $FILE
service sphinxsearch stop
echo "manual" > /etc/init/sphinxsearch.conf.override
a2dissite elsa
# Remove ELSA link from Squert
mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e 'delete from filters where alias="ELSA";'
# Add ELK link to Squert
MYSQL="mysql --defaults-file=/etc/mysql/debian.cnf -Dsecurityonion_db -e"
URL="/app/kibana#/discover?_g=(refreshInterval:(display:Off,pause:!f,value:0),time:(from:now-7d,mode:quick,to:now))&_a=(columns:!(_source),index:'logstash-*',interval:auto,query:'\${var}',sort:!('@timestamp',desc))"
HEXVAL=$(xxd -pu -c 256 <<< "$URL")
$MYSQL "REPLACE INTO filters (type,username,global,name,notes,alias,filter) VALUES ('url','','1','454C4B','','ELK','$HEXVAL');"
service apache2 restart

header "Reconfiguring syslog-ng to send logs to ELK"
FILE="/etc/syslog-ng/syslog-ng.conf"
cp $FILE $FILE.elsa
sed -i '/^destination d_elsa/a destination d_logstash_bro { tcp("127.0.0.1" port(6050) template("$(format-json --scope selected_macros --scope nv_pairs --exclude DATE --key ISODATE)\n")); };' $FILE
sed -i 's/log { destination(d_elsa); };/log { destination(d_logstash_bro); };/' $FILE
sed -i '/rewrite(r_host);/d' $FILE
sed -i '/rewrite(r_cisco_program);/d' $FILE
sed -i '/rewrite(r_snare);/d' $FILE
sed -i '/rewrite(r_from_pipes);/d' $FILE
sed -i '/rewrite(r_pipes);/d' $FILE
sed -i '/parser(p_db);/d' $FILE
sed -i '/rewrite(r_extracted_host);/d' $FILE
service syslog-ng restart

header "Updating OSSEC rules"
cp elk-test/ossec/securityonion_rules.xml /var/ossec/rules/
chown root:ossec /var/ossec/rules/securityonion_rules.xml
chmod 660 /var/ossec/rules/securityonion_rules.xml
service ossec-hids-server restart

header "Configuring Kibana"
es_host=localhost
es_port=9200
kibana_index=.kibana
kibana_version=$( jq -r '.version' < /opt/kibana/package.json )
kibana_build=$(jq -r '.build.number' < /opt/kibana/package.json )
until curl -s -XGET http://${es_host}:${es_port}/_cluster/health > /dev/null ; do
    wait_step=$(( ${wait_step} + 1 ))
    if [ ${wait_step} -gt ${max_wait} ]; then
        echo "ERROR: elasticsearch server not available for more than ${max_wait} seconds."
        exit 5
    fi
    sleep 1;
done
curl -s -XDELETE http://${es_host}:${es_port}/${kibana_index}/config/${kibana_version}
curl -s -XDELETE http://${es_host}:${es_port}/${kibana_index}
#curl -XPUT http://${es_host}:${es_port}/${kibana_index}/index-pattern/logstash-* -d@elk-test/kibana/index-pattern.json; echo; echo
curl -XPUT http://${es_host}:${es_port}/${kibana_index}/config/${kibana_version} -d@elk-test/kibana/config.json; echo; echo
cd $DIR/elk-test/kibana/dashboards/
sh load.sh
cd $DIR

if [ -f /etc/nsm/sensortab ]; then
	NUM_INTERFACES=`grep -v "^#" /etc/nsm/sensortab | wc -l`
	if [ $NUM_INTERFACES -gt 0 ]; then
		header "Replaying pcaps in /opt/samples/ to create logs"
		INTERFACE=`grep -v "^#" /etc/nsm/sensortab | head -1 | awk '{print $4}'`
		for i in /opt/samples/*.pcap /opt/samples/markofu/*.pcap /opt/samples/mta/*.pcap; do
		echo -n "." 
		tcpreplay -i $INTERFACE -M10 $i >/dev/null 2>&1
		done
		echo
	fi
fi

header "All done!"
cat << EOF

After a minute or two, you should be able to access Kibana via the following URL:
https://localhost/app/kibana

When prompted for username and password, use the same credentials that you use to login to Sguil and Squert.

You will automatically start on our Overview dashboard and you will see links to other dashboards as well.  These dashboards are designed to work at 1024x768 screen resolution in order to maximize compatibility.

As you search through the data in Kibana, you should see Bro logs, syslog, and Snort alerts.  Logstash should have parsed out most fields in most Bro logs and Snort alerts.

Notice that the source_ip and destination_ip fields are hyperlinked.  These hyperlinks will take you to a dashboard that will help you analyze the traffic relating to that particular IP address.

UID fields are also hyperlinked.  This hyperlink will start a new Kibana search for that particular UID.  In the case of Bro UIDs this will show you all Bro logs related to that particular connection.

Each log entry also has an _id field that is hyperlinked.  This hyperlink will take you to CapMe, allowing you to request full packet capture for any arbitrary log type!  This assumes that the log is for tcp or udp traffic that was seen by Bro and Bro recorded it correctly in its conn.log.  CapMe should try to do the following:
* retrieve the _id from Elasticsearch
* parse out timestamp
* if Bro log, parse out the CID, otherwise parse out src IP, src port, dst IP, and dst port
* query Elasticsearch for those terms and try to find the corresponding bro_conn log
* parse out sensor name (hostname-interface)
* send a request to sguild to request pcap from that sensor name

Previously, in Squert, you could pivot from an IP address to ELSA.  That pivot has been removed and replaced with a pivot to ELK.

Happy Hunting!

EOF
