#include <memory>
#include "node.h"
#include "loranode.h"
#include "objecttype.h"

using namespace std;

bool LoraNode::s_createdTypes = false;
std::shared_ptr<BaseObject> LoraNode::s_pSensorCollectionInstDecl;
std::shared_ptr<Property> LoraNode::s_pDevEUIInstDecl;
LoraNode::LoraNode(OpcUa::NodeId nodeId,
                   OpcUa::LocalizedText browseName,
                   OpcUa::LocalizedText displayName,
                   OpcUa::LocalizedText description,
                   NodeManager * pNodeManager,
                   OpcUa::NodeId parentNode,
                   OpcUa::NodeId parentReferenceType)
: BaseObject(nodeId, browseName, displayName, description, pNodeManager, parentNode, parentReferenceType, true)
{
    createTypes(pNodeManager);
    setType(s_pObjType->getNodeId());
    // create member variables
    m_pSensorCollection = std::make_shared<BaseObject>(NodeId(browseName.Text + "." + "SensorCollection", pNodeManager->getNamespaceIdx()),
                                                              LocalizedText("SensorCollection"),
                                                              LocalizedText("SensorCollection"),
                                                              LocalizedText("SensorCollection"),
                                                              pNodeManager,
                                                              getNodeId(),
                                                              ObjectId::HasComponent);
    m_pDevEUI = std::make_shared<Property>(s_pDevEUIInstDecl.get(),
                                           NodeId(browseName.Text + "." + "DevEUI", pNodeManager->getNamespaceIdx()),
                                           pNodeManager,
                                           getNodeId());


}

void LoraNode::createTypes(NodeManager * pNodeManager)
{
    s_pObjType = make_shared<ObjectType>(NodeId("LoraNodeType", pNodeManager->getNamespaceIdx()),
                                         LocalizedText("LoraNodeType"),
                                         LocalizedText("LoraNodeType"),
                                         LocalizedText("LoraNodeType"),
                                         false,
                                         ObjectId::BaseObjectType,
                                         ReferenceId::HasSubtype,
                                         pNodeManager);
    s_pDevEUIInstDecl = make_shared<Property>(NodeId("DevEUID", pNodeManager->getNamespaceIdx()),
                                              LocalizedText("DevEUID"),
                                              LocalizedText("DevEUID"),
                                              LocalizedText("LoraWan IEEE EUI64 Device ID"),
                                              pNodeManager,
                                              s_pObjType->getNodeId(),
                                              ObjectId::UInt64,
                                              true);


    s_pSensorCollectionInstDecl = make_shared<BaseObject>(NodeId("SensorCollection", pNodeManager->getNamespaceIdx()),
                                                          LocalizedText("SensorCollection"),
                                                          LocalizedText("SensorCollection"),
                                                          LocalizedText("SensorCollection"),
                                                          pNodeManager,
                                                          s_pObjType->getNodeId(),
                                                          ObjectId::HasComponent);

}

int LoraNode::addSensor(shared_ptr<Node> pSensorNode)
{
    m_pSensorCollection->addReference(m_pSensorCollection->getNodeId(), pSensorNode->getNodeId(), ObjectId::HasComponent, NodeClass::Object);
}

LoraNode::~LoraNode()
{

}
