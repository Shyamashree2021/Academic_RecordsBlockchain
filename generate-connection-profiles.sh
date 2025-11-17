#!/bin/bash
# =================================================================
#  Generate Connection Profiles for All Organizations
#  Purpose: Create connection profile JSON files for SDK clients
# =================================================================

set -e

BASEDIR=$(dirname "$0")
cd "$BASEDIR"

ORGS_DIR="organizations/peerOrganizations"

echo "======================================================"
echo "🔗 Generating Connection Profiles"
echo "======================================================"

# Function to generate connection profile for an organization
generate_connection_profile() {
    local ORG_NAME=$1
    local ORG_DOMAIN=$2
    local ORG_MSP=$3
    local PEER_PORT=$4
    local CA_PORT=$5
    
    echo "Generating connection profile for ${ORG_NAME}..."
    
    local ORG_DIR="${ORGS_DIR}/${ORG_DOMAIN}"
    local OUTPUT_FILE="${ORG_DIR}/connection-${ORG_NAME}.json"
    
    # Get CA certificate
    local CA_CERT=$(cat "${ORG_DIR}/ca/ca.${ORG_DOMAIN}-cert.pem" | sed 's/$/\\n/' | tr -d '\n')
    
    # Get TLS CA certificate
    local TLSCA_CERT=$(cat "${ORG_DIR}/tlsca/tlsca.${ORG_DOMAIN}-cert.pem" | sed 's/$/\\n/' | tr -d '\n')
    
    # Create connection profile JSON
    cat > "${OUTPUT_FILE}" <<EOF
{
    "name": "${ORG_NAME}-network",
    "version": "1.0.0",
    "client": {
        "organization": "${ORG_MSP}",
        "connection": {
            "timeout": {
                "peer": {
                    "endorser": "300"
                },
                "orderer": "300"
            }
        }
    },
    "organizations": {
        "${ORG_MSP}": {
            "mspid": "${ORG_MSP}",
            "peers": [
                "peer0.${ORG_DOMAIN}"
            ],
            "certificateAuthorities": [
                "ca.${ORG_DOMAIN}"
            ]
        }
    },
    "peers": {
        "peer0.${ORG_DOMAIN}": {
            "url": "grpcs://localhost:${PEER_PORT}",
            "tlsCACerts": {
                "pem": "${TLSCA_CERT}"
            },
            "grpcOptions": {
                "ssl-target-name-override": "peer0.${ORG_DOMAIN}",
                "hostnameOverride": "peer0.${ORG_DOMAIN}"
            }
        }
    },
    "certificateAuthorities": {
        "ca.${ORG_DOMAIN}": {
            "url": "https://localhost:${CA_PORT}",
            "caName": "ca-${ORG_NAME}",
            "tlsCACerts": {
                "pem": ["${CA_CERT}"]
            },
            "httpOptions": {
                "verify": false
            }
        }
    }
}
EOF
    
    echo "✅ Created: ${OUTPUT_FILE}"
}

# Generate connection profiles for each organization
# Format: generate_connection_profile ORG_NAME ORG_DOMAIN ORG_MSP PEER_PORT CA_PORT

generate_connection_profile "nitwarangal" "nitwarangal.nitw.edu" "NITWarangalMSP" "7051" "8054"
generate_connection_profile "departments" "departments.nitw.edu" "DepartmentsMSP" "9051" "9054"
generate_connection_profile "verifiers" "verifiers.nitw.edu" "VerifiersMSP" "11051" "11054"

echo ""
echo "======================================================"
echo "✅ All connection profiles generated successfully!"
echo "======================================================"
echo ""
echo "Connection profiles created:"
echo "  - ${ORGS_DIR}/nitwarangal.nitw.edu/connection-nitwarangal.json"
echo "  - ${ORGS_DIR}/departments.nitw.edu/connection-departments.json"
echo "  - ${ORGS_DIR}/verifiers.nitw.edu/connection-verifiers.json"
echo ""
