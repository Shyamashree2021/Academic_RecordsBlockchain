#!/bin/bash
# =================================================================
#  NIT WARANGAL - Academic Records Blockchain Network Script (v2)
#  Author: Prince Kumar & GitHub Copilot
#  Purpose: Automate full Hyperledger Fabric workflow with Fabric CA
# =================================================================

set -e
set -o pipefail

# Import utils
. scripts/utils.sh

# --- Global Variables ---
CHANNEL_NAME="academic-records-channel"
CHAINCODE_NAME="academic-records"
CHAINCODE_PATH="./chaincode-go/academic-records"
CHAINCODE_LANG="golang"
CHAINCODE_LABEL="academic_records_2.0" # Updated with Department-based architecture
CHAINCODE_VERSION="2.0"
ORDERER_CA_TLS_PATH="${PWD}/organizations/ordererOrganizations/nitw.edu/orderers/orderer.nitw.edu/tls/tlscacerts/tls-localhost-7054-ca-orderer.pem"
ORDERER_ADMIN_MSP_PATH="${PWD}/organizations/ordererOrganizations/nitw.edu/users/Admin@nitw.edu/msp"
ORDERER_ADDR="orderer.nitw.edu:7050"

# --- Peer Variables ---
NITW_PEER0_ADDR="peer0.nitwarangal.nitw.edu:7051"
NITW_PEER0_TLS_PATH="${PWD}/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt"
DEPT_PEER0_ADDR="peer0.departments.nitw.edu:9051"
DEPT_PEER0_TLS_PATH="${PWD}/organizations/peerOrganizations/departments.nitw.edu/peers/peer0.departments.nitw.edu/tls/ca.crt"
VERI_PEER0_ADDR="peer0.verifiers.nitw.edu:11051"
VERI_PEER0_TLS_PATH="${PWD}/organizations/peerOrganizations/verifiers.nitw.edu/peers/peer0.verifiers.nitw.edu/tls/ca.crt"

# ------------------------------------------------------------
# 1. Clean previous setup
# ------------------------------------------------------------
cleanup() {
    printHeader "🧹 Cleaning network and artifacts..."
    # Stop and remove containers, volumes, and networks
    if [ -f "docker/docker-compose-net.yaml" ]; then
        docker-compose -f docker/docker-compose-net.yaml down --volumes --remove-orphans 2>/dev/null
    fi
    # Cleanup any remaining containers
    docker ps -aq | xargs -r docker rm -f 2>/dev/null || true
    # Cleanup any remaining networks
    docker network ls | grep "nit-warangal-network" | awk '{print $1}' | xargs -r docker network rm 2>/dev/null || true
    # Remove generated artifacts
    rm -rf organizations channel-artifacts system-genesis-block *.tar.gz 2>/dev/null || true
    # Recreate empty directories
    mkdir -p channel-artifacts system-genesis-block
    successln "✓ Clean complete"
}

# ------------------------------------------------------------
# 2. Generate Identities using Fabric CA
# ------------------------------------------------------------
createIdentities() {
    printHeader "🧬 Generating identities using Fabric CA..."
    # Start CA containers
    docker-compose -f docker/docker-compose-net.yaml up -d ca_orderer ca_nitwarangal ca_departments ca_verifiers
    infoln "Waiting for Fabric CAs to initialize..."
    sleep 10 # Wait for CAs to start and generate their certificates

    # Make the enrollment script executable
    chmod +x scripts/registerEnroll.sh

    # Execute enrollment script
    ./scripts/registerEnroll.sh

    # Generate connection profiles for all organizations
    infoln "Generating connection profiles..."
    chmod +x generate-connection-profiles.sh
    ./generate-connection-profiles.sh

    successln "✓ Identities and connection profiles generated successfully"
}

# ------------------------------------------------------------
# 3. Start Network (Peers, Orderer)
# ------------------------------------------------------------
startNetwork() {
    printHeader "🚀 Starting Fabric network..."
    # Start the network (peers, orderer, cli)
    # The CAs should already be running from the previous step
    docker-compose -f docker/docker-compose-net.yaml up -d orderer.nitw.edu peer0.nitwarangal.nitw.edu peer0.departments.nitw.edu peer0.verifiers.nitw.edu cli
    sleep 5
    docker ps --format "table {{.Names}}\t{{.Status}}"
    successln "✓ Network containers are running"
}

# ------------------------------------------------------------
# 4. Create Genesis Block, Channel & Join Peers
# ------------------------------------------------------------
createChannelAndJoinPeers() {
    printHeader "🔗 Creating channel '$CHANNEL_NAME' and joining peers..."

    # Use the CLI container to create the channel and join peers
    docker exec cli bash -c "
        # Create channel genesis block using configtxgen
        export FABRIC_CFG_PATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/configtx
        configtxgen -profile AcademicRecordsChannel -outputBlock ./channel-artifacts/${CHANNEL_NAME}.block -channelID ${CHANNEL_NAME}
        unset FABRIC_CFG_PATH
        
        # Join orderer to channel using osnadmin
        osnadmin channel join --channelID ${CHANNEL_NAME} --config-block ./channel-artifacts/${CHANNEL_NAME}.block -o orderer.nitw.edu:7053 --ca-file /opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/nitw.edu/orderers/orderer.nitw.edu/tls/ca.crt --client-cert /opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/nitw.edu/orderers/orderer.nitw.edu/tls/server.crt --client-key /opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/nitw.edu/orderers/orderer.nitw.edu/tls/server.key
        
        # Set environment for NITWarangal Admin
        export CORE_PEER_TLS_ENABLED=true
        export CORE_PEER_LOCALMSPID='NITWarangalMSP'
        export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/users/Admin@nitwarangal.nitw.edu/msp
        export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt
        export CORE_PEER_ADDRESS=peer0.nitwarangal.nitw.edu:7051

        # Join NITWarangal peer
        peer channel join -b ./channel-artifacts/${CHANNEL_NAME}.block

        # Set environment for Departments Admin and join peer
        export CORE_PEER_LOCALMSPID='DepartmentsMSP'
        export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/users/Admin@departments.nitw.edu/msp
        export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/peers/peer0.departments.nitw.edu/tls/ca.crt
        export CORE_PEER_ADDRESS=peer0.departments.nitw.edu:9051
        peer channel join -b ./channel-artifacts/${CHANNEL_NAME}.block

        # Set environment for Verifiers Admin and join peer
        export CORE_PEER_LOCALMSPID='VerifiersMSP'
        export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/users/Admin@verifiers.nitw.edu/msp
        export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/peers/peer0.verifiers.nitw.edu/tls/ca.crt
        export CORE_PEER_ADDRESS=peer0.verifiers.nitw.edu:11051
        peer channel join -b ./channel-artifacts/${CHANNEL_NAME}.block
    "
    successln "✓ All peers joined channel '$CHANNEL_NAME'"
}

# ------------------------------------------------------------
# 5. Deploy Chaincode
# ------------------------------------------------------------
deployChaincode() {
    printHeader "📦 Deploying chaincode..."

    # Vendor Go dependencies
    (cd ${CHAINCODE_PATH} && GO111MODULE=on go mod vendor)
    infoln "✓ Chaincode dependencies vendored"

    # Package and install chaincode on all peers
    docker exec cli bash -c "
        # Package the chaincode
        peer lifecycle chaincode package ${CHAINCODE_NAME}.tar.gz --path /opt/gopath/src/github.com/hyperledger/fabric/peer/chaincode-go/academic-records --lang ${CHAINCODE_LANG} --label ${CHAINCODE_LABEL}
        
        # Install on NITWarangal peer
        export CORE_PEER_LOCALMSPID=NITWarangalMSP
        export CORE_PEER_ADDRESS=${NITW_PEER0_ADDR}
        export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt
        export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/users/Admin@nitwarangal.nitw.edu/msp
        peer lifecycle chaincode install ${CHAINCODE_NAME}.tar.gz

        # Install on Departments peer
        export CORE_PEER_LOCALMSPID=DepartmentsMSP
        export CORE_PEER_ADDRESS=${DEPT_PEER0_ADDR}
        export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/peers/peer0.departments.nitw.edu/tls/ca.crt
        export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/users/Admin@departments.nitw.edu/msp
        peer lifecycle chaincode install ${CHAINCODE_NAME}.tar.gz

        # Install on Verifiers peer
        export CORE_PEER_LOCALMSPID=VerifiersMSP
        export CORE_PEER_ADDRESS=${VERI_PEER0_ADDR}
        export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/peers/peer0.verifiers.nitw.edu/tls/ca.crt
        export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/users/Admin@verifiers.nitw.edu/msp
        peer lifecycle chaincode install ${CHAINCODE_NAME}.tar.gz
    "
    successln "✓ Chaincode packaged and installed on all peers"

    # --- Approve and Commit ---
    # Query installed to get package ID
    PACKAGE_ID=$(docker exec cli peer lifecycle chaincode queryinstalled | grep "Package ID: ${CHAINCODE_LABEL}" | sed -n 's/Package ID: \(.*\), Label:.*/\1/p')
    infoln "Chaincode Package ID: ${PACKAGE_ID}"

    # Approve for each organization
    docker exec cli bash -c "
        #Set orderer CA TLS path for container
        ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/nitw.edu/orderers/orderer.nitw.edu/tls/tlscacerts/tls-localhost-7054-ca-orderer.pem
        
        # Approve for NITWarangal
        # Endorsement Policy: Requires 2 of 3 organizations (NITWarangalMSP, DepartmentsMSP, VerifiersMSP)
        export CORE_PEER_LOCALMSPID=NITWarangalMSP
        export CORE_PEER_ADDRESS=${NITW_PEER0_ADDR}
        export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt
        export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/users/Admin@nitwarangal.nitw.edu/msp
        peer lifecycle chaincode approveformyorg -o ${ORDERER_ADDR} --ordererTLSHostnameOverride orderer.nitw.edu --tls --cafile \$ORDERER_CA --channelID ${CHANNEL_NAME} --name ${CHAINCODE_NAME} --version ${CHAINCODE_VERSION} --package-id '${PACKAGE_ID}' --sequence 1 --signature-policy \"OR('NITWarangalMSP.peer','DepartmentsMSP.peer','VerifiersMSP.peer')\" --collections-config /opt/gopath/src/github.com/hyperledger/fabric/peer/collections_config.json

        # Approve for Departments
        export CORE_PEER_LOCALMSPID=DepartmentsMSP
        export CORE_PEER_ADDRESS=${DEPT_PEER0_ADDR}
        export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/peers/peer0.departments.nitw.edu/tls/ca.crt
        export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/users/Admin@departments.nitw.edu/msp
        peer lifecycle chaincode approveformyorg -o ${ORDERER_ADDR} --ordererTLSHostnameOverride orderer.nitw.edu --tls --cafile \$ORDERER_CA --channelID ${CHANNEL_NAME} --name ${CHAINCODE_NAME} --version ${CHAINCODE_VERSION} --package-id '${PACKAGE_ID}' --sequence 1 --signature-policy \"OR('NITWarangalMSP.peer','DepartmentsMSP.peer','VerifiersMSP.peer')\" --collections-config /opt/gopath/src/github.com/hyperledger/fabric/peer/collections_config.json

        # Approve for Verifiers
        export CORE_PEER_LOCALMSPID=VerifiersMSP
        export CORE_PEER_ADDRESS=${VERI_PEER0_ADDR}
        export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/peers/peer0.verifiers.nitw.edu/tls/ca.crt
        export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/users/Admin@verifiers.nitw.edu/msp
        peer lifecycle chaincode approveformyorg -o ${ORDERER_ADDR} --ordererTLSHostnameOverride orderer.nitw.edu --tls --cafile \$ORDERER_CA --channelID ${CHANNEL_NAME} --name ${CHAINCODE_NAME} --version ${CHAINCODE_VERSION} --package-id '${PACKAGE_ID}' --sequence 1 --signature-policy \"OR('NITWarangalMSP.peer','DepartmentsMSP.peer','VerifiersMSP.peer')\" --collections-config /opt/gopath/src/github.com/hyperledger/fabric/peer/collections_config.json
    "
    successln "✓ Chaincode approved by all orgs"

    # Commit the chaincode definition
    # NOTE: Explicit OR policy allows any single peer to endorse, but channel MAJORITY policy still requires 2 orgs for transaction validation
    docker exec cli bash -c "
        ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/nitw.edu/orderers/orderer.nitw.edu/tls/tlscacerts/tls-localhost-7054-ca-orderer.pem
        NITW_TLS=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt
        DEPT_TLS=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/peers/peer0.departments.nitw.edu/tls/ca.crt
        VERI_TLS=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/peers/peer0.verifiers.nitw.edu/tls/ca.crt
        
        peer lifecycle chaincode commit -o ${ORDERER_ADDR} --ordererTLSHostnameOverride orderer.nitw.edu --tls --cafile \$ORDERER_CA --channelID ${CHANNEL_NAME} --name ${CHAINCODE_NAME} --version ${CHAINCODE_VERSION} --sequence 1 --signature-policy \"OR('NITWarangalMSP.peer','DepartmentsMSP.peer','VerifiersMSP.peer')\" --collections-config /opt/gopath/src/github.com/hyperledger/fabric/peer/collections_config.json --peerAddresses ${NITW_PEER0_ADDR} --tlsRootCertFiles \$NITW_TLS --peerAddresses ${DEPT_PEER0_ADDR} --tlsRootCertFiles \$DEPT_TLS --peerAddresses ${VERI_PEER0_ADDR} --tlsRootCertFiles \$VERI_TLS
    "
    successln "✓ Chaincode committed to channel"
}

# ------------------------------------------------------------
# 6. Test Chaincode (ABAC & PDC)
# ------------------------------------------------------------
testChaincode() {
    printHeader "🧪 Testing Chaincode (ABAC and Private Data)..."

    # Container paths for TLS certificates
    ORDERER_CA_CONTAINER=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/nitw.edu/orderers/orderer.nitw.edu/tls/tlscacerts/tls-localhost-7054-ca-orderer.pem
    NITW_TLS_CONTAINER=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt
    DEPT_TLS_CONTAINER=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/peers/peer0.departments.nitw.edu/tls/ca.crt
    VERI_TLS_CONTAINER=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/peers/peer0.verifiers.nitw.edu/tls/ca.crt

    # 1. Create a student record using a user from NITWarangal org (dean with role attribute)
    infoln "Attempting to create a student as 'Admin' from NITWarangalMSP..."
    docker exec -e CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/users/Admin@nitwarangal.nitw.edu/msp \
    -e CORE_PEER_ADDRESS=${NITW_PEER0_ADDR} \
    -e CORE_PEER_LOCALMSPID="NITWarangalMSP" \
    -e CORE_PEER_TLS_ROOTCERT_FILE=${NITW_TLS_CONTAINER} \
    cli peer chaincode invoke -o ${ORDERER_ADDR} --ordererTLSHostnameOverride orderer.nitw.edu --tls --cafile ${ORDERER_CA_CONTAINER} -C ${CHANNEL_NAME} -n ${CHAINCODE_NAME} \
    --peerAddresses ${NITW_PEER0_ADDR} --tlsRootCertFiles ${NITW_TLS_CONTAINER} \
    --peerAddresses ${DEPT_PEER0_ADDR} --tlsRootCertFiles ${DEPT_TLS_CONTAINER} \
    -c '{"function":"CreateStudent","Args":["CS21B001","John Doe","CSE","2021","[email protected]","GENERAL"]}' \
    --transient "{\"aadhaarHash\":\"$(echo -n '1234567890abcdef' | base64)\",\"phone\":\"$(echo -n '9876543210' | base64)\",\"personalEmail\":\"$(echo -n '[email protected]' | base64)\"}"
    successln "✓ Student creation invoked"
    sleep 3

    # 2. Query the public student details as a verifier
    infoln "Querying public student data as a verifier..."
    docker exec -e CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/users/User1@verifiers.nitw.edu/msp \
    -e CORE_PEER_ADDRESS=${VERI_PEER0_ADDR} \
    -e CORE_PEER_LOCALMSPID="VerifiersMSP" \
    -e CORE_PEER_TLS_ROOTCERT_FILE=${VERI_TLS_CONTAINER} \
    cli peer chaincode query -C ${CHANNEL_NAME} -n ${CHAINCODE_NAME} -c '{"Args":["GetStudent","CS21B001"]}'
    
    # 3. Attempt to query private details as a verifier (should fail)
    infoln "Attempting to query private data as a verifier (should fail)..."
    docker exec -e CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/users/User1@verifiers.nitw.edu/msp \
    -e CORE_PEER_ADDRESS=${VERI_PEER0_ADDR} \
    -e CORE_PEER_LOCALMSPID="VerifiersMSP" \
    -e CORE_PEER_TLS_ROOTCERT_FILE=${VERI_TLS_CONTAINER} \
    cli peer chaincode query -C ${CHANNEL_NAME} -n ${CHAINCODE_NAME} -c '{"Args":["GetStudentPrivateDetails","CS21B001"]}' || trueln "✓ As expected, verifier cannot access private data"

    # 4. Query private details as NITWarangal admin (should succeed)
    infoln "Querying private data as NITWarangal admin (should succeed)..."
    docker exec -e CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/users/Admin@nitwarangal.nitw.edu/msp \
    -e CORE_PEER_ADDRESS=${NITW_PEER0_ADDR} \
    -e CORE_PEER_LOCALMSPID="NITWarangalMSP" \
    -e CORE_PEER_TLS_ROOTCERT_FILE=${NITW_TLS_CONTAINER} \
    cli peer chaincode query -C ${CHANNEL_NAME} -n ${CHAINCODE_NAME} -c '{"Args":["GetStudentPrivateDetails","CS21B001"]}'

    successln "✓ Chaincode tests completed successfully!"
}


# --- Main execution logic ---
case "$1" in
  up)
    cleanup
    createIdentities
    startNetwork
    createChannelAndJoinPeers
    deployChaincode
    testChaincode
    printHeader "🎉🎉🎉 NETWORK IS UP AND RUNNING! 🎉🎉🎉"
    ;;
  clean)
    cleanup
    ;;
  *)
    echo "Usage: ./network.sh up | clean"
    exit 1
    ;;
esac