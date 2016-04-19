#include "nmlora.h"

NmLora::NmLora()
: NodeManager("http://reniver.eu/lora-opcua-server")
{

}

void NmLora::afterStartup(OpcUa::NodeManagementServices::SharedPtr pNodeManagementService)
{

}

void NmLora::beforeShutdown(OpcUa::NodeManagementServices::SharedPtr pNodeManagementService)
{
}
