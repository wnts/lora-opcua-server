#ifndef SRC_NMLORA_H_
#define SRC_NMLORA_H_

#include "nodemanager.h"

class NmLora : public NodeManager {
	public:
		NmLora();
		virtual void afterStartup(OpcUa::NodeManagementServices::SharedPtr pNodeManagementService);
		virtual void beforeShutdown(OpcUa::NodeManagementServices::SharedPtr pNodeManagementService);
};



#endif /* SRC_NMLORA_H_ */
