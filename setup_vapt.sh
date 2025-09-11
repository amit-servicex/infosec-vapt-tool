
#!/bin/bash


echo "🔧 Setting up environment variables..."


export PYTHONPATH=/home/amitks/infosec-vapt-tool:$PYTHONPATH



export ZAP_DOCKER_IMAGE="ghcr.io/zaproxy/zaproxy:stable"

export ARTIFACTS_DIR=/tmp/nuclei_artifacts

export ENABLE_DEBUG_FILE=0

export WRAPPER_DEBUG=1

chmod +x /home/amitks/infosec-vapt-tool/core/plugins/web/nuclei/main.py

head -n1 /home/amitks/infosec-vapt-tool/core/plugins/web/nuclei/main.py

# must be:  #!/usr/bin/env python3

#Uncomment if scanning localhost services
export ZAP_DOCKER_EXTRA_ARGS="--network host"

export DEBUG_ZAP=1

#SQLMap (default)

export SQLMAP_DOCKER_IMAGE="sqlmapproject/sqlmap"

#Alternative ParrotSec image
docker pull parrotsec/sqlmap
export SQLMAP_DOCKER_IMAGE="parrotsec/sqlmap"
#FFUF

export FFUF_DOCKER_IMAGE="secsi/ffuf:2.0.0"


#Nuclei (wrapper around official ProjectDiscovery image)

export NUCLEI_DOCKER_IMAGE="whz/vapt-nuclei:0.1.0"

#Reporting Module

export REPORT_HTML_IMAGE="whz/vapt-report-html:0.1.0"

echo "✅ Environment variables set."

echo "🐳 Building local Docker images..."

#Reporting Module

export REPORT_HTML_IMAGE="whz/vapt-report-html:0.1.0"

echo "✅ Environment variables set."

echo "🐳 Building local Docker images..."

#Build ZAP wrapper module

docker build -t whz/vapt-zap:0.1.0 core/plugins/web/zap

#Build Nuclei wrapper module

docker build -t whz/vapt-nuclei:0.1.0 core/plugins/web/nuclei

#Build HTML reporting module

docker build -t whz/vapt-report-html:0.1.0 core/reporting/report_module

echo "✅ Docker images built."

echo "📥 Pulling official tool images..."

#ZAP (stable)

docker pull ghcr.io/zaproxy/zaproxy:stable

#SQLMap official

docker pull parrotsec/sqlmap

#FFUF

docker pull secsi/ffuf:2.0.0

#(Optional) ParrotSec SQLMap
docker pull parrotsec/sqlmap

echo "✅ Tool images pulled."

echo "🎉 VAPT setup complete! You can now run pipelines."
