#include "loranode.h"

LoraNode::LoraNode(OpcUa::NodeId nodeId,
				   OpcUa::LocalizedText browseName,
				   OpcUa::LocalizedText displayName,
				   OpcUa::LocalizedText description,
				   NodeManager * pNodeManager,
				   OpcUa::NodeId parentNode,
				   OpcUa::NodeId parentReferenceType)
: BaseObject(nodeId, browseName, displayName, description, pNodeManager, parentNode, parentReferenceType, false)
{
	createTypes(pNodeManager);
	setType(s_pObjType->getNodeId());
	// create member variables
}

void LoraNode::createTypes(NodeManager * pNodeManager)
{

}

LoraNode::~LoraNode()
{

}
