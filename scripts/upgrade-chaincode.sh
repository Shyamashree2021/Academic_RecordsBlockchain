#!/bin/bash
# =================================================================
#  Upgrade Chaincode Script - For updating chaincode without network restart
#  Usage: ./scripts/upgrade-chaincode.sh <new_version> [sequence]
#  Example: ./scripts/upgrade-chaincode.sh 2.0 2
# =================================================================

set -e

# Check arguments
if [ -z "$1" ]; then
    echo "❌ Usage: ./scripts/upgrade-chaincode.sh <new_version> [sequence]"
    echo "Example: ./scripts/upgrade-chaincode.sh 2.0 2"
    exit 1
fi

NEW_VERSION=$1
SEQUENCE=${2:-2}  # Default to sequence 2 if not provided
CHAINCODE_NAME="academic-records"
CHAINCODE_PATH="./chaincode-go/academic-records"
CHAINCODE_LANG="golang"
CHAINCODE_LABEL="academic_records_${NEW_VERSION}"
CHANNEL_NAME="academic-records-channel"
ORDERER_ADDR="orderer.nitw.edu:7050"

# Peer addresses
NITW_PEER0_ADDR="peer0.nitwarangal.nitw.edu:7051"
DEPT_PEER0_ADDR="peer0.departments.nitw.edu:9051"
VERI_PEER0_ADDR="peer0.verifiers.nitw.edu:11051"

echo "=================================================="
echo "📦 Upgrading Chaincode to Version ${NEW_VERSION}"
echo "=================================================="

# Step 1: Vendor dependencies
echo "📚 Vendoring Go dependencies..."
(cd ${CHAINCODE_PATH} && GO111MODULE=on go mod vendor)
echo "✓ Dependencies vendored"

# Step 2: Package the updated chaincode
echo "📦 Packaging chaincode..."
docker exec cli bash -c "
    peer lifecycle chaincode package ${CHAINCODE_NAME}_${NEW_VERSION}.tar.gz \
        --path /opt/gopath/src/github.com/hyperledger/fabric/peer/chaincode-go/academic-records \
        --lang ${CHAINCODE_LANG} \
        --label ${CHAINCODE_LABEL}
"
echo "✓ Chaincode packaged"

# Step 3: Install on all peers
echo "🔧 Installing chaincode on all peers..."
docker exec cli bash -c "
    # Install on NITWarangal peer
    export CORE_PEER_LOCALMSPID=NITWarangalMSP
    export CORE_PEER_ADDRESS=${NITW_PEER0_ADDR}
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/users/Admin@nitwarangal.nitw.edu/msp
    peer lifecycle chaincode install ${CHAINCODE_NAME}_${NEW_VERSION}.tar.gz

    # Install on Departments peer
    export CORE_PEER_LOCALMSPID=DepartmentsMSP
    export CORE_PEER_ADDRESS=${DEPT_PEER0_ADDR}
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/peers/peer0.departments.nitw.edu/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/users/Admin@departments.nitw.edu/msp
    peer lifecycle chaincode install ${CHAINCODE_NAME}_${NEW_VERSION}.tar.gz

    # Install on Verifiers peer
    export CORE_PEER_LOCALMSPID=VerifiersMSP
    export CORE_PEER_ADDRESS=${VERI_PEER0_ADDR}
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/peers/peer0.verifiers.nitw.edu/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/users/Admin@verifiers.nitw.edu/msp
    peer lifecycle chaincode install ${CHAINCODE_NAME}_${NEW_VERSION}.tar.gz
"
echo "✓ Chaincode installed on all peers"

# Step 4: Query installed to get package ID
echo "🔍 Getting package ID..."
PACKAGE_ID=$(docker exec cli peer lifecycle chaincode queryinstalled | grep "Package ID: ${CHAINCODE_LABEL}" | sed -n 's/Package ID: \(.*\), Label:.*/\1/p')
echo "✓ Package ID: ${PACKAGE_ID}"

# Step 5: Approve for all organizations
echo "✅ Approving chaincode for all organizations..."
docker exec cli bash -c "
    ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/nitw.edu/orderers/orderer.nitw.edu/tls/tlscacerts/tls-localhost-7054-ca-orderer.pem
    
    # Approve for NITWarangal
    export CORE_PEER_LOCALMSPID=NITWarangalMSP
    export CORE_PEER_ADDRESS=${NITW_PEER0_ADDR}
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/users/Admin@nitwarangal.nitw.edu/msp
    peer lifecycle chaincode approveformyorg -o ${ORDERER_ADDR} --ordererTLSHostnameOverride orderer.nitw.edu \
        --tls --cafile \$ORDERER_CA \
        --channelID ${CHANNEL_NAME} \
        --name ${CHAINCODE_NAME} \
        --version ${NEW_VERSION} \
        --package-id '${PACKAGE_ID}' \
        --sequence ${SEQUENCE} \
        --signature-policy \"OR('NITWarangalMSP.peer','DepartmentsMSP.peer','VerifiersMSP.peer')\" \
        --collections-config /opt/gopath/src/github.com/hyperledger/fabric/peer/collections_config.json

    # Approve for Departments
    export CORE_PEER_LOCALMSPID=DepartmentsMSP
    export CORE_PEER_ADDRESS=${DEPT_PEER0_ADDR}
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/peers/peer0.departments.nitw.edu/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/users/Admin@departments.nitw.edu/msp
    peer lifecycle chaincode approveformyorg -o ${ORDERER_ADDR} --ordererTLSHostnameOverride orderer.nitw.edu \
        --tls --cafile \$ORDERER_CA \
        --channelID ${CHANNEL_NAME} \
        --name ${CHAINCODE_NAME} \
        --version ${NEW_VERSION} \
        --package-id '${PACKAGE_ID}' \
        --sequence ${SEQUENCE} \
        --signature-policy \"OR('NITWarangalMSP.peer','DepartmentsMSP.peer','VerifiersMSP.peer')\" \
        --collections-config /opt/gopath/src/github.com/hyperledger/fabric/peer/collections_config.json

    # Approve for Verifiers
    export CORE_PEER_LOCALMSPID=VerifiersMSP
    export CORE_PEER_ADDRESS=${VERI_PEER0_ADDR}
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/peers/peer0.verifiers.nitw.edu/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/users/Admin@verifiers.nitw.edu/msp
    peer lifecycle chaincode approveformyorg -o ${ORDERER_ADDR} --ordererTLSHostnameOverride orderer.nitw.edu \
        --tls --cafile \$ORDERER_CA \
        --channelID ${CHANNEL_NAME} \
        --name ${CHAINCODE_NAME} \
        --version ${NEW_VERSION} \
        --package-id '${PACKAGE_ID}' \
        --sequence ${SEQUENCE} \
        --signature-policy \"OR('NITWarangalMSP.peer','DepartmentsMSP.peer','VerifiersMSP.peer')\" \
        --collections-config /opt/gopath/src/github.com/hyperledger/fabric/peer/collections_config.json
"
echo "✓ Chaincode approved by all organizations"

# Step 6: Commit the chaincode
echo "🚀 Committing chaincode to channel..."
docker exec cli bash -c "
    ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/ordererOrganizations/nitw.edu/orderers/orderer.nitw.edu/tls/tlscacerts/tls-localhost-7054-ca-orderer.pem
    NITW_TLS=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/nitwarangal.nitw.edu/peers/peer0.nitwarangal.nitw.edu/tls/ca.crt
    DEPT_TLS=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/departments.nitw.edu/peers/peer0.departments.nitw.edu/tls/ca.crt
    VERI_TLS=/opt/gopath/src/github.com/hyperledger/fabric/peer/organizations/peerOrganizations/verifiers.nitw.edu/peers/peer0.verifiers.nitw.edu/tls/ca.crt
    
    peer lifecycle chaincode commit -o ${ORDERER_ADDR} --ordererTLSHostnameOverride orderer.nitw.edu \
        --tls --cafile \$ORDERER_CA \
        --channelID ${CHANNEL_NAME} \
        --name ${CHAINCODE_NAME} \
        --version ${NEW_VERSION} \
        --sequence ${SEQUENCE} \
        --signature-policy \"OR('NITWarangalMSP.peer','DepartmentsMSP.peer','VerifiersMSP.peer')\" \
        --collections-config /opt/gopath/src/github.com/hyperledger/fabric/peer/collections_config.json \
        --peerAddresses ${NITW_PEER0_ADDR} --tlsRootCertFiles \$NITW_TLS \
        --peerAddresses ${DEPT_PEER0_ADDR} --tlsRootCertFiles \$DEPT_TLS \
        --peerAddresses ${VERI_PEER0_ADDR} --tlsRootCertFiles \$VERI_TLS
"
echo "✓ Chaincode committed successfully"

echo ""
echo "=================================================="
echo "🎉 Chaincode upgraded to version ${NEW_VERSION}"
echo "=================================================="
echo ""
echo "📋 Summary:"
echo "   Version: ${NEW_VERSION}"
echo "   Sequence: ${SEQUENCE}"
echo "   Package ID: ${PACKAGE_ID}"
echo ""
echo "🧪 Test the new chaincode function:"
echo "   docker exec cli peer chaincode query -C academic-records-channel -n academic-records -c '{\"Args\":[\"GetStudentsByDepartment\",\"CSE\"]}'"
echo ""
