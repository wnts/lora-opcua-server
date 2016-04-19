#ifndef SRC_LORANODE_H_
#define SRC_LORANODE_H_
#include <memory>
#include "node.h"
#include "baseobject.h"
#include "property.h"
#include "nodemanager.h"
#include "temperaturesensor.h"


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
		int addSensor(std::shared_ptr<Node> pSensorNode);
		OpcUa::NodeId getType();
	protected:
		static bool s_createdTypes;
		static std::shared_ptr<BaseObject> s_pSensorCollectionInstDecl;
		static std::shared_ptr<Property> s_pDevEUIInstDecl;
		std::shared_ptr<BaseObject> m_pSensorCollection;
		std::shared_ptr<Property> m_pDevEUI;
	private:
		void createTypes(NodeManager * pNodeManager);

};



#endif /* SRC_LORANODE_H_ */
