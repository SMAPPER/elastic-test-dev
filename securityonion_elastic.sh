#!/bin/bash

# Configure Elastic on Security Onion

# Check for prerequisites
if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run using sudo!"
        exit 1
fi

# Make a directory to store downloads
DIR="/opt/elastic"
mkdir -p $DIR
cd $DIR
PCAP_DIR="$DIR/pcap"

# Define a banner to separate sections
banner="========================================================================="

header() {
        echo
        printf '%s\n' "$banner" "$*" "$banner"
}

REPO="elastic-test"
if [ "$1" == "dev" ]; then
        URL="https://github.com/dougburks/$REPO.git"
        DOCKERHUB="dougburks"
else
        URL="https://github.com/Security-Onion-Solutions/$REPO.git"
        DOCKERHUB="securityonionsolutions"
fi
EOF

clear
cat << EOF 
This QUICK and DIRTY script is designed to allow you to quickly and easily experiment with the Elastic stack (Elasticsearch, Logstash, and Kibana) on Security Onion.

This script assumes that you've already installed the latest Security Onion 14.04.5.2 ISO image as follows:
* (1) management interface with full Internet access
* (1) sniffing interface (separate from management interface)

This script will do the following:
* install Docker and download Docker images for Elasticsearch, Logstash, and Kibana
* import our custom visualizations and dashboards
* configure syslog-ng to send logs to Logstash on port 6050
* configure Apache as a reverse proxy for Kibana and authenticate users against Sguil database
* update CapMe to leverage that single sign on (SSO) and integrate with Elasticsearch
* update Squert to use SSO
* replay sample pcaps to provide data for testing

Depending on the speed of your hardware and Internet connection, this process will take at least 10 minutes.

TODO
For the current TODO list, please see:
https://github.com/Security-Onion-Solutions/security-onion/issues/1095

HARDWARE REQUIREMENTS
The Elastic stack requires more hardware than ELSA.  For best results on your test VM, you'll probably want at LEAST 2 CPU cores and 8GB of RAM.

THANKS
Special thanks to Justin Henderson for his Logstash configs and installation guide!
https://github.com/SMAPPER/Logstash-Configs

Special thanks to Phil Hagen for all his work on SOF-ELK!
https://github.com/philhagen/sof-elk

WARNINGS AND DISCLAIMERS
* This technology PREVIEW is PRE-ALPHA, BLEEDING EDGE, and TOTALLY UNSUPPORTED!
* If this breaks your system, you get to keep both pieces!
* This script is a work in progress and is in constant flux.
* This script is intended to build a quick prototype proof of concept so you can see what our ultimate Elastic configuration might look like.  This configuration will change drastically over time leading up to the final release.
* Do NOT run this on a system that you care about!
* Do NOT run this on a system that has data that you care about!
* This script should only be run on a TEST box with TEST data!
* This script is only designed for standalone boxes and does NOT support distributed deployments.
* Use of this script may result in nausea, vomiting, or a burning sensation.
 
Once you've read all of the WARNINGS AND DISCLAIMERS above, please type AGREE to proceed:
EOF
read INPUT
if [ "$INPUT" != "AGREE" ] ; then exit 0; fi

header "Installing git"
apt-get update > /dev/null
apt-get install -y git > /dev/null
echo "Done!"

header "Cloning git repo"
git clone $URL
cp -av $REPO/usr/sbin/* /usr/sbin/
chmod +x /usr/sbin/so-elastic-*
echo "Done!"

. /usr/sbin/so-elastic-download

cat << EOF
You're now ready to run through Setup.

Once you've run through both phases of Setup (network configuration, reboot, service configuration), you can then replay some sample pcaps using the following command:
sudo /usr/sbin/so-elastic-replay-pcaps

Once you have some data, you should then be able to login to Kibana:
https://localhost/app/kibana

Please press Enter to proceed with the Setup process.

EOF

read input

/usr/sbin/sosetup
