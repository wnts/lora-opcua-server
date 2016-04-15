#ifndef SRC_LORANODE_H_
#define SRC_LORANODE_H_

#include "baseobject.h"
#include "nodemanager.h"

/**
 * Class representing a Lora Node
 */
class LoraNode : public BaseObject
{
	public:
		LoraNode(OpcUa::NodeId nodeId,
				 OpcUa::LocalizedText browseName,
				 OpcUa::LocalizedText description,
				 OpcUa::LocalizedText,
				 NodeManager * pNodeManager,
				 OpcUa::NodeId parentNode,
				 OpcUa::NodeId parentReferenceType);
		~LoraNode();
		OpcUa::NodeId getType();
	protected:
		bool s_createdTypes = false;
	private:
		void createTypes(NodeManager * pNodeManager);
		ObjectType * s_pObjType;

};



#endif /* SRC_LORANODE_H_ */
